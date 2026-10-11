#!/usr/bin/env python3
"""Opt-in real sing-box + temporary OpenSSH server; no external VPS/system service."""
import argparse
import http.server
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(); p.add_argument('--sing-box',default=shutil.which('sing-box')); args=p.parse_args()
if not args.sing_box or not shutil.which('sshd'): raise SystemExit('Need sing-box and sshd; not run.')

def port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]

class Handler(http.server.BaseHTTPRequestHandler):
    count=0
    def do_GET(self):
        Handler.count+=1; self.send_response(200); self.send_header('Content-Length','7'); self.end_headers(); self.wfile.write(b'via-ssh')
    def log_message(self,*a): pass

with tempfile.TemporaryDirectory(prefix='cproxy SSH integration ') as directory:
    d=Path(directory); processes=[]; server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        for name,kind in [('client','ed25519'),('host','ed25519'),('host-ecdsa','ecdsa'),('wrong','ed25519')]:
            subprocess.run(['ssh-keygen','-q','-t',kind,'-N','','-f',str(d/name)],check=True)
        (d/'authorized_keys').write_text((d/'client.pub').read_text()); (d/'authorized_keys').chmod(0o600)
        ssh_port=port(); proxy_port=port()
        (d/'sshd.conf').write_text(f'''ListenAddress 127.0.0.1
Port {ssh_port}
HostKey "{d/'host'}"
HostKey "{d/'host-ecdsa'}"
PidFile "{d/'sshd.pid'}"
AuthorizedKeysFile "{d/'authorized_keys'}"
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AllowTcpForwarding local
PermitRootLogin prohibit-password
LogLevel ERROR
''')
        # StrictModes=no is ONLY for this disposable /tmp fixture, not a production setting.
        log=(d/'sshd.log').open('w')
        daemon=subprocess.Popen([shutil.which('sshd'),'-D','-e','-f',str(d/'sshd.conf')],stderr=log)
        processes.append(daemon); time.sleep(.3)
        if daemon.poll() is not None: raise RuntimeError((d/'sshd.log').read_text())
        pub=' '.join((d/'host.pub').read_text().split()[:2])
        params=dict(server='127.0.0.1',ssh_port=ssh_port,user=pwd.getpwuid(os.getuid()).pw_name,
                    key=str(d/'client'),host_key=pub,proxy_port=proxy_port,domains=[],cidrs=[])
        rendered=subprocess.run(['bash','-c','source "$1/linux/common.sh"; render_config "$2"','test',str(ROOT),json.dumps(params)],text=True,capture_output=True,check=True)
        config=d/'config.json'; config.write_text(rendered.stdout)
        subprocess.run([args.sing_box,'check','-c',str(config)],check=True)
        def start():
            output=(d/'sing-box.log').open('w')
            process=subprocess.Popen([args.sing_box,'run','-c',str(config)],stdout=output,stderr=output)
            processes.append(process)
            for _ in range(30):
                try:
                    with socket.create_connection(('127.0.0.1',proxy_port),.1): return process
                except OSError: time.sleep(.1)
            raise RuntimeError('Proxy not listening: '+(d/'sing-box.log').read_text())
        def request(proxy):
            return subprocess.run(['curl','-q','--silent','--fail','--max-time','5','--noproxy','','--proxy',proxy,
                                   f'http://localhost:{server.server_port}/'],text=True,capture_output=True)
        process=start()
        for proxy in [f'http://127.0.0.1:{proxy_port}',f'socks5h://127.0.0.1:{proxy_port}']:
            result=request(proxy)
            if result.returncode!=0 or result.stdout!='via-ssh': raise RuntimeError(f'Forwarding failed: proxy={proxy} code={result.returncode} body={result.stdout!r} stderr={result.stderr!r} singbox={(d/"sing-box.log").read_text()} sshd={(d/"sshd.log").read_text()}')
        process.terminate(); process.wait(timeout=5)
        # Wrong host pin with a real server must not contact the HTTP target.
        wrong=json.loads(config.read_text()); wrong['outbounds'][0]['host_key']=[' '.join((d/'wrong.pub').read_text().split()[:2])]
        config.write_text(json.dumps(wrong)); process=start(); count=Handler.count
        result=request(f'http://127.0.0.1:{proxy_port}')
        assert result.returncode!=0 and Handler.count==count, 'Host mismatch leaked direct traffic'
        process.terminate(); process.wait(timeout=5)
        assert request(f'http://127.0.0.1:{proxy_port}').returncode!=0, 'Stopped proxy fell back'
        print('PASS: real multi-key SSH pin, HTTP, SOCKS5, host mismatch rejection, stopped proxy failure')
    finally:
        server.shutdown()
        for process in reversed(processes):
            if process.poll() is None: process.terminate(); process.wait(timeout=5)
