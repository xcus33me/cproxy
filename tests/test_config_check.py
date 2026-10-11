import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
BINARY=os.environ.get('SING_BOX_BINARY') or shutil.which('sing-box')

class RealConfigTest(unittest.TestCase):
    @unittest.skipUnless(BINARY and shutil.which('ssh-keygen'), 'sing-box or ssh-keygen missing; real check not run')
    def test_real_sing_box_check(self):
        with tempfile.TemporaryDirectory(prefix='cproxy config ') as directory:
            d=Path(directory); key=d/'key'
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
            host=' '.join((d/'key.pub').read_text().split()[:2])
            params=dict(server='vps.example.org',ssh_port=22,user='proxy',key=str(key),host_key=host,
                        proxy_port=2080,domains=['local'],cidrs=['10.0.0.0/8'])
            rendered=subprocess.run(['bash','-c','source "$1/linux/common.sh"; render_config "$2"','test',str(ROOT),json.dumps(params)],capture_output=True,text=True,check=True)
            config=d/'config.json'; config.write_text(rendered.stdout)
            result=subprocess.run([BINARY,'check','-c',str(config)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
