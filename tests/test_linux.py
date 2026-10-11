import json
import os
from pathlib import Path
import subprocess
import tempfile
import pty
import unittest
import time

ROOT = Path(__file__).resolve().parents[1]
HOSTKEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF8CGAfWLRTdqdxvGlFtZk7UlGJKCvtaBHwgbLLMRFoh'

class LinuxFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cproxy test ')
        self.home = Path(self.tmp.name)
        self.env = dict(os.environ, HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / '.config'),
                        XDG_RUNTIME_DIR=str(self.home / 'runtime'))
        self.bin = self.home / 'bin'; self.bin.mkdir()
        self.env['PATH'] = str(self.bin) + ':' + os.environ['PATH']
        self.key = self.home / 'key with spaces'; self.key.write_text('fixture')
        self.key.chmod(0o600)
    def tearDown(self):
        self.tmp.cleanup()
    def run_bash(self, script, *args):
        return subprocess.run(['bash', '-c', script, 'test', *map(str, args)], env=self.env,
                              text=True, capture_output=True)
    def render(self, **change):
        p = dict(server='vps.example.org', ssh_port=22, user='proxy', key=str(self.key),
                 host_key=HOSTKEY, proxy_port=2080, domains=['local'], cidrs=['10.0.0.0/8'])
        p.update(change)
        source = f'source "{ROOT}/linux/common.sh"; render_config "$1" "$2"'
        return self.run_bash(source, json.dumps(p), ROOT / 'config/sing-box.json.tpl')
    def fixture(self, name, code):
        p = self.bin / name; p.write_text('#!/bin/bash\n' + code); p.chmod(0o755)
    def install_config(self):
        result = self.render(); self.assertEqual(result.returncode, 0, result.stderr)
        self.config = self.home / '.config/selective-proxy'; self.config.mkdir(parents=True)
        (self.config / 'config.json').write_text(result.stdout)
        (self.config / 'settings.json').write_text(json.dumps({'expected_ips':['203.0.113.9'],
                                                'local_tests':[], 'key_mode':'unattended'}))
        (self.config / '.cproxy-owner').write_text('cproxy-v1')
        unit=self.home/'.config/systemd/user/selective-proxy.service'
        unit.parent.mkdir(parents=True); unit.write_text('# Managed by cproxy\n')
        self.fixture('systemctl','exit 0\n')
class LinuxTests(LinuxFixture):
    def test_wrapper_refuses_foreign_proxy_when_service_stopped(self):
        self.install_config()
        self.fixture('systemctl', 'exit 3\n')
        self.fixture('curl', 'echo 203.0.113.9\n')
        self.fixture('claude', 'touch "$HOME/claude-ran"\n')
        r=subprocess.run(['bash',str(ROOT/'linux/claude-vpn.sh')],env=self.env,capture_output=True)
        self.assertNotEqual(r.returncode,0)
        self.assertFalse((self.home/'claude-ran').exists())
    def test_wrapper_allows_equal_ips_without_explicit_ip_pin(self):
        self.install_config()
        data=json.loads((self.config/'settings.json').read_text()); data['expected_ips']=[]
        (self.config/'settings.json').write_text(json.dumps(data))
        self.fixture('curl', 'echo 203.0.113.9\n')
        self.fixture('claude', 'touch "$HOME/claude-ran"\n')
        r=subprocess.run(['bash',str(ROOT/'linux/claude-vpn.sh')],env=self.env,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertTrue((self.home/'claude-ran').exists())
    def test_readiness_reports_network_error_only_once(self):
        self.install_config()
        self.fixture('curl', 'exit 7\n'); self.fixture('systemctl', 'exit 0\n')
        self.fixture('timeout', 'exit 0\n'); self.fixture('sleep', 'exit 0\n')
        r=self.run_bash(f'source "{ROOT}/linux/common.sh"; load_config; wait_ready')
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(r.stderr.count('HTTP-прокси не выходит'),1,r.stderr)
    def test_render_preserves_escaped_values_and_fail_closed(self):
        r = self.render(user='user"name', key=str(self.home / 'key "quoted"'))
        self.assertEqual(r.returncode, 0, r.stderr)
        c = json.loads(r.stdout)
        self.assertEqual(c['outbounds'][0]['user'], 'user"name')
        self.assertEqual(c['inbounds'][0]['listen'], '127.0.0.1')
        self.assertFalse(c['inbounds'][0]['set_system_proxy'])
        self.assertEqual(c['route']['final'], 'ssh-out')
        self.assertEqual(c['outbounds'][0]['host_key'], [HOSTKEY])
        self.assertEqual(c['outbounds'][0]['host_key_algorithms'], ['ssh-ed25519'])
        self.assertEqual(c['route']['rules'][1]['outbound'], 'ssh-out')
    def test_invalid_inputs_rejected(self):
        for change in ({'host_key':''}, {'proxy_port':0}, {'ssh_port':65536},
                       {'cidrs':['0.0.0.0/0']}, {'domains':['com']}, {'server':'-evil'},
                       {'domains':['anthropic.com']}, {'domains':['api.anthropic.com']}, {'cidrs':['8.8.8.8/32']}):
            with self.subTest(change=change):
                r = self.render(**change)
                self.assertNotEqual(r.returncode, 0)
    def test_config_guard_rejects_public_direct_and_unpinned(self):
        self.install_config()
        c = json.loads((self.config / 'config.json').read_text())
        for change in ('final', 'host_key', 'listen'):
            d = json.loads(json.dumps(c))
            if change == 'final': d['route']['final'] = 'direct'
            if change == 'host_key': d['outbounds'][0]['host_key'] = []
            if change == 'listen': d['inbounds'][0]['listen'] = '0.0.0.0'
            file = self.home / 'bad.json'; file.write_text(json.dumps(d))
            r = self.run_bash(f'source "{ROOT}/linux/common.sh"; validate_config "$1"', file)
            self.assertNotEqual(r.returncode, 0, change)
    def test_cli_unknown_and_missing_config(self):
        r = subprocess.run(['bash', str(ROOT / 'linux/proxyctl'), 'nonsense'], env=self.env, capture_output=True)
        self.assertEqual(r.returncode, 2)
        r = subprocess.run(['bash', str(ROOT / 'linux/proxyctl'), 'test'], env=self.env, capture_output=True)
        self.assertNotEqual(r.returncode, 0)
    def test_wrapper_blocks_failed_proxy(self):
        self.install_config()
        self.fixture('curl', 'exit 7\n')
        self.fixture('claude', 'touch "$HOME/claude-ran"\n')
        r = subprocess.run(['bash', str(ROOT / 'linux/claude-vpn.sh')], env=self.env, capture_output=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.home / 'claude-ran').exists())
    def test_wrapper_env_arguments_and_exit_code(self):
        self.install_config()
        self.fixture('curl', 'echo 203.0.113.9\n')
        self.fixture('claude', 'env > "$HOME/child-env"\nprintf "%s\\n" "$@" > "$HOME/args"\nexit 37\n')
        self.env.update(NO_PROXY='*', no_proxy='*', https_proxy='http://wrong', ALL_PROXY='socks5://wrong')
        r = subprocess.run(['bash', str(ROOT / 'linux/claude-vpn.sh'), '--help', 'a b', 'x"y'], env=self.env, capture_output=True)
        self.assertEqual(r.returncode, 37, r.stderr)
        e = (self.home / 'child-env').read_text()
        self.assertIn('HTTPS_PROXY=http://127.0.0.1:2080', e)
        self.assertIn('https_proxy=http://127.0.0.1:2080', e)
        self.assertNotIn('NO_PROXY=*', e)
        self.assertNotIn('ALL_PROXY=socks5://wrong', e)
        self.assertEqual((self.home / 'args').read_text().splitlines(), ['--help', 'a b', 'x"y'])
    def test_browser_uses_dedicated_profile_and_pins_prefs(self):
        self.install_config(); self.fixture('curl','echo 203.0.113.9\n')
        self.fixture('firefox','printf "%s\n" "$@" > "$HOME/browser-args"\n')
        main=self.home/'.mozilla/firefox/main/prefs.js'; main.parent.mkdir(parents=True); main.write_text('unchanged')
        r=subprocess.run(['bash',str(ROOT/'linux/proxyctl'),'browser'],env=self.env,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr)
        profile=self.config/'firefox-Claude'
        argsfile=self.home/'browser-args'
        for _ in range(100):
            if argsfile.exists() and argsfile.stat().st_size: break
            time.sleep(0.01)
        self.assertIn(str(profile),argsfile.read_text().splitlines())
        self.assertEqual(main.read_text(),'unchanged')
        prefs=(profile/'user.js').read_text()
        self.assertIn('user_pref("network.proxy.socks5_remote_dns", true);',prefs)
        self.assertIn('user_pref("network.proxy.allow_bypass", false);',prefs)
        self.assertIn('user_pref("network.proxy.ssl", "");',prefs)
    def test_session_settings_cannot_unlock_original_key_in_place(self):
        self.install_config()
        (self.config/'settings.json').write_text(json.dumps(dict(key_mode='session',expected_ips=[],local_tests=[],encrypted_key_path=str(self.key))))
        r=subprocess.run(['bash',str(ROOT/'linux/proxyctl'),'unlock'],env=self.env,capture_output=True)
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(self.key.read_text(),'fixture')
        self.assertIn(b'Runtime',r.stderr)
    def test_diagnostics_reject_different_proxy_ipv6_outputs(self):
        self.install_config()
        self.fixture('curl', 'if [[ "$*" == *api6* ]]; then if [[ "$*" == *socks5h* ]]; then echo 2001:db8::2; else echo 2001:db8::1; fi; else echo 203.0.113.9; fi\n')
        r=subprocess.run(['bash',str(ROOT/'linux/proxyctl'),'test'],env=self.env,capture_output=True)
        self.assertNotEqual(r.returncode,0)
    def test_wrapper_rejects_unexpected_ip(self):
        self.install_config(); self.fixture('curl', 'echo 198.51.100.3\n')
        self.fixture('claude', 'touch "$HOME/claude-ran"\n')
        r = subprocess.run(['bash', str(ROOT / 'linux/claude-vpn.sh')], env=self.env, capture_output=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.home / 'claude-ran').exists())

class InstallerTests(LinuxFixture):
    def interactive_install(self, key=None, ssh_port='', *args):
        wizard=self.home/'wizard.json'
        wizard.write_text(json.dumps(dict(server='vps.example.org',ssh_port=int(ssh_port or 22),user='proxy',key=key or str(self.key),key_mode='unattended',proxy_port=2080)))
        return self.install(*args,'--wizard-file',wizard)
    def test_first_install_automatically_pins_key_without_extra_question(self):
        self.prepare()
        r = self.interactive_install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        conf = self.home/'.config/selective-proxy/config.json'
        self.assertEqual(json.loads(conf.read_text())['outbounds'][0]['host_key'], [HOSTKEY])
        self.assertFalse((self.home/'.ssh/known_hosts').exists())
    def test_interactive_key_path_accepts_home_shorthand(self):
        self.prepare()
        r = self.interactive_install('~/key with spaces')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        conf = self.home/'.config/selective-proxy/config.json'
        self.assertEqual(json.loads(conf.read_text())['outbounds'][0]['private_key_path'], str(self.key))
    def test_hashed_known_host_with_custom_port_is_reused_without_modification(self):
        self.prepare()
        known = self.home/'.ssh/known_hosts'; known.parent.mkdir()
        known.write_text('[vps.example.org]:2222 ' + HOSTKEY + '\n')
        subprocess.run(['/usr/bin/ssh-keygen', '-H', '-f', str(known)], check=True, capture_output=True)
        before = known.read_bytes()
        r = self.interactive_install(None, '2222')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(known.read_bytes(), before)
    def test_changed_known_host_is_rejected_without_installing(self):
        self.prepare()
        known = self.home/'.ssh/known_hosts'; known.parent.mkdir()
        known.write_text('vps.example.org ' + HOSTKEY.replace('IF8C', 'IG8C') + '\n')
        r = self.interactive_install()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.home/'.config/selective-proxy/config.json').exists())
        self.assertFalse((self.home/'active').exists())
    def test_revoked_or_certificate_known_host_does_not_bootstrap(self):
        self.prepare()
        known = self.home/'.ssh/known_hosts'; known.parent.mkdir()
        for marker in ('@revoked', '@cert-authority'):
            with self.subTest(marker=marker):
                known.write_text(marker + ' vps.example.org ' + HOSTKEY + '\n')
                r = self.interactive_install()
                self.assertNotEqual(r.returncode, 0)
                self.assertFalse((self.home/'.config/selective-proxy/config.json').exists())
    def test_reconfigure_does_not_replace_existing_pin_for_same_server(self):
        self.prepare()
        r = self.install('--params', self.params); self.assertEqual(r.returncode, 0, r.stderr)
        conf = self.home/'.config/selective-proxy/config.json'; before = conf.read_bytes()
        self.fixture('ssh-keyscan', 'echo "vps.example.org ' + HOSTKEY.replace('IF8C', 'IG8C') + '"\n')
        r = self.interactive_install(None, '', '--reconfigure')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(conf.read_bytes(), before)
        self.assertTrue((self.home/'active').exists())
    def prepare(self):
        self.fixture('sing-box', 'if [[ $1 == check && -e "$HOME/fail-check" ]]; then exit 1; fi\necho "sing-box version 1.12.0"\n')
        self.fixture('ssh-keygen', 'if [[ $1 == -F ]]; then /usr/bin/ssh-keygen \"$@\"; else exit 0; fi\n')
        self.fixture('ssh-keyscan', 'echo "vps.example.org ' + HOSTKEY + '"\n')
        self.fixture('curl', 'if [[ -e "$HOME/fail-network" ]]; then exit 7; fi\necho 203.0.113.9\n')
        self.fixture('systemctl', 'echo "$*" >> "$HOME/systemctl-log"\ncase "$*" in *is-active*) test -f "$HOME/active";; *is-enabled*) test -f "$HOME/enabled";; *enable*) touch "$HOME/enabled";; *disable*) rm -f "$HOME/enabled";; *stop*) rm -f "$HOME/active";; *start*) touch "$HOME/active";; *) exit 0;; esac\n')
        self.fixture('sleep', 'exit 0\n')
        self.fixture('timeout', 'if [[ "$*" == *2080* ]]; then test -f "$HOME/active"; else exit 0; fi\n')
        p = dict(server='vps.example.org',ssh_port=22,user='proxy',key=str(self.key),
                 host_key=HOSTKEY,proxy_port=2080,domains=['local'],cidrs=['10.0.0.0/8'],
                 expected_ips=['203.0.113.9'],key_mode='unattended')
        self.params = self.home / 'params.json'; self.params.write_text(json.dumps(p))
    def install(self, *args):
        return subprocess.run(['bash',str(ROOT/'linux/install.sh'),*map(str,args)],env=self.env,text=True,capture_output=True)
    def session_install(self):
        main, slave = pty.openpty()
        try:
            return subprocess.run(['bash',str(ROOT/'linux/install.sh'),'--params',str(self.params)],
                                  env=self.env,stdin=slave,text=True,capture_output=True)
        finally: os.close(main); os.close(slave)
    def test_failed_session_reconfiguration_preserves_runtime_key(self):
        self.prepare(); (self.home/'runtime').mkdir()
        p=json.loads(self.params.read_text()); p['key_mode']='session'; self.params.write_text(json.dumps(p))
        r=self.session_install(); self.assertEqual(r.returncode,0,r.stderr)
        runtime=self.home/'runtime/selective-proxy/session.key'; before=runtime.read_bytes()
        self.key.write_text('new key'); (self.home/'fail-check').touch()
        r=self.session_install(); self.assertNotEqual(r.returncode,0)
        self.assertEqual(runtime.read_bytes(),before)
    def test_failed_new_session_removes_decrypted_copy(self):
        self.prepare(); (self.home/'runtime').mkdir()
        p=json.loads(self.params.read_text()); p['key_mode']='session'; self.params.write_text(json.dumps(p))
        (self.home/'fail-check').touch()
        r=self.session_install(); self.assertNotEqual(r.returncode,0)
        self.assertFalse((self.home/'runtime/selective-proxy/session.key').exists())
    def test_ui_binary_and_installed_backends_are_published_and_removed(self):
        self.prepare(); self.env['CPROXY_UI_BINARY']='/usr/bin/true'
        r=self.install('--params',self.params); self.assertEqual(r.returncode,0,r.stderr)
        app=self.home/'.config/selective-proxy'
        self.assertTrue((app/'install.sh').exists()); self.assertTrue((app/'selective-proxy.service').exists())
        launcher=self.home/'.local/bin/cproxy'
        r=subprocess.run([str(launcher),'--help'],env=self.env,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr)
        r=subprocess.run(['bash',str(app/'install.sh'),'--wizard-file',str(self.params)],env=self.env,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr)
        r=subprocess.run(['bash',str(ROOT/'linux/uninstall.sh')],env=self.env,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertFalse(launcher.exists()); self.assertFalse((app/'cproxy-ui').exists())
        self.assertFalse((app/'claude-vpn.fish').exists())
        self.assertTrue(self.key.exists())
    def test_install_twice_preserves_settings_and_config(self):
        self.prepare()
        r=self.install('--params',self.params); self.assertEqual(r.returncode,0,r.stderr)
        conf=self.home/'.config/selective-proxy/config.json'
        settings=conf.with_name('settings.json')
        data=json.loads(settings.read_text()); data['local_tests']=['http://127.0.0.1:8000/']; settings.write_text(json.dumps(data))
        c=json.loads(conf.read_text()); c['log']['level']='error'; conf.write_text(json.dumps(c))
        before=conf.read_text()
        r=self.install(); self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(conf.read_text(),before)
        self.assertEqual(json.loads(settings.read_text())['local_tests'],['http://127.0.0.1:8000/'])
        self.assertEqual(conf.stat().st_mode & 0o777,0o600)
        self.assertTrue((self.home/'.local/bin/proxyctl').exists())
    def test_check_failure_leaves_working_config(self):
        self.prepare(); r=self.install('--params',self.params); self.assertEqual(r.returncode,0,r.stderr)
        conf=self.home/'.config/selective-proxy/config.json'; before=conf.read_bytes()
        (self.home/'fail-check').touch()
        r=self.install('--params',self.params); self.assertNotEqual(r.returncode,0)
        self.assertEqual(conf.read_bytes(),before)
        self.assertTrue((self.home/'active').exists())
    def test_network_failure_rolls_back_running_install(self):
        self.prepare(); r=self.install('--params',self.params); self.assertEqual(r.returncode,0,r.stderr)
        conf=self.home/'.config/selective-proxy/config.json'; before=conf.read_bytes()
        (self.home/'fail-network').touch()
        r=self.install('--params',self.params); self.assertNotEqual(r.returncode,0)
        self.assertEqual(conf.read_bytes(),before)
        self.assertTrue((self.home/'active').exists())
    def test_busy_port_and_unowned_directory_rejected(self):
        self.prepare(); (self.home/'active').touch()
        r=self.install('--params',self.params); self.assertNotEqual(r.returncode,0)
        (self.home/'active').unlink()
        d=self.home/'.config/selective-proxy'; d.mkdir(parents=True); (d/'unrelated').touch()
        r=self.install('--params',self.params); self.assertNotEqual(r.returncode,0)
        self.assertTrue((d/'unrelated').exists())
    def test_stop_works_with_corrupt_config(self):
        self.prepare(); r=self.install('--params',self.params); self.assertEqual(r.returncode,0,r.stderr)
        (self.home/'.config/selective-proxy/config.json').write_text('corrupt')
        r=subprocess.run(['bash',str(ROOT/'linux/proxyctl'),'stop'],env=self.env,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertFalse((self.home/'active').exists())
    def test_uninstall_preserves_profile_key_and_unrelated_file(self):
        self.prepare(); r=self.install('--params',self.params); self.assertEqual(r.returncode,0,r.stderr)
        d=self.home/'.config/selective-proxy'; (d/'unrelated').touch()
        (d/'firefox-Claude').mkdir(); (d/'firefox-Claude/prefs.js').touch()
        r=subprocess.run(['bash',str(ROOT/'linux/uninstall.sh')],env=self.env,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertTrue(self.key.exists()); self.assertTrue((d/'unrelated').exists())
        self.assertTrue((d/'firefox-Claude/prefs.js').exists())
        self.assertFalse((self.home/'.local/bin/proxyctl').exists())
        r=self.install('--params',self.params); self.assertEqual(r.returncode,0,r.stderr)
        self.assertTrue((d/'firefox-Claude/prefs.js').exists())


if __name__ == '__main__': unittest.main()
