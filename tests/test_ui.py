"""Real terminal smoke tests. No service, packages or external connection involved."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import struct
import subprocess
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TerminalUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('go') or not shutil.which('ssh-keygen'):
            raise unittest.SkipTest('Go/OpenSSH missing')
        cls.build = tempfile.TemporaryDirectory(prefix='cproxy binary ')
        cls.binary = str(Path(cls.build.name) / 'cproxy')
        subprocess.run(['go', 'build', '-o', cls.binary, './cmd/cproxy'], cwd=ROOT, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cproxy terminal ')
        self.home = Path(self.temp.name)
        key = self.home / '.ssh/id_ed25519'
        key.parent.mkdir()
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        self.env = dict(os.environ, HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / 'config'),
                        TMPDIR=str(self.home), CPROXY_SOURCE_DIR=str(ROOT), TERM='xterm-256color')
        self.output = b''
        self.process = None

    def tearDown(self):
        if self.process:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait()
            os.close(self.fd)
        self.temp.cleanup()

    def start(self, *args):
        self.fd, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 32, 100, 0, 0))
        self.process = subprocess.Popen([self.binary, *args], stdin=slave, stdout=slave, stderr=slave, env=self.env)
        os.close(slave)

    def read_until(self, text, timeout=5):
        start = len(self.output)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if select.select([self.fd], [], [], 0.1)[0]:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    break
                self.output += data
                if b'\x1b[6n' in data:
                    os.write(self.fd, b'\x1b[1;1R')
            if text.encode() in self.output[start:]:
                return
        self.fail(f'{text!r} not shown: {self.output[-4000:].decode(errors="replace")}')

    def send(self, data):
        os.write(self.fd, data)
        time.sleep(0.06)

    def assert_cancelled_without_installation(self):
        self.send(b'\x1b')
        self.assertEqual(self.process.wait(timeout=5), 130)
        self.assertFalse((self.home / 'config/selective-proxy').exists())
        self.assertFalse(list(self.home.glob('cproxy-wizard-*')))

    def test_escape_leaves_no_configuration(self):
        self.start('setup')
        self.read_until('Адрес вашего сервера')
        self.assert_cancelled_without_installation()

    def test_review_back_and_edit(self):
        self.start('setup')
        self.read_until('Адрес вашего сервера')
        for keys in (b'wrong.example.org\r', b'proxy\r', b'\r', b'\r'):
            self.send(keys)
        self.read_until('Сервер: wrong.example.org:22')
        self.send(b'\x1b[B\r')  # Review -> edit.
        self.read_until('Адрес вашего сервера')
        self.send(b'\x01\x0bcorrect.example.org\r')  # Ctrl+A, Ctrl+K replace the field.
        for _ in range(3):
            self.send(b'\r')
        self.read_until('Сервер: correct.example.org:22')
        self.assert_cancelled_without_installation()

    def test_shift_tab_returns_to_previous_input(self):
        self.start('setup')
        self.read_until('Адрес вашего сервера')
        self.send(b'wrong.example.org\r')
        self.send(b'\x1b[Z')
        self.send(b'\x01\x0bcorrect.example.org\r')
        self.send(b'proxy\r')
        self.send(b'\r')
        self.send(b'\r')
        self.read_until('Сервер: correct.example.org:22')
        self.assert_cancelled_without_installation()

    def test_existing_installation_opens_menu_and_can_exit(self):
        app = self.home / 'config/selective-proxy'
        app.mkdir(parents=True)
        (app / 'config.json').write_text(json.dumps(dict(inbounds=[dict(listen_port=2080)],
            outbounds=[dict(server='vps.example.org', server_port=22, user='proxy', private_key_path='/unused')])) )
        self.start()
        self.read_until('Что хотите сделать?')
        self.assertIn('Открыть Claude в Firefox'.encode(), self.output)
        for _ in range(4):
            self.send(b'\x1b[B')
        self.send(b'\r')
        self.assertEqual(self.process.wait(timeout=5), 0)
