"""Exercise the one-shot client in temporary directories; never runs the real Nginx."""
import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

client_path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'app/pipeline_client.py').resolve()
spec = importlib.util.spec_from_file_location('certops_pipeline_client_qa', client_path)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl'), 'Linux and OpenSSL are required')
class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certops-client-qa-')
        self.root = pathlib.Path(self.temp.name)
        self.config = {'target_id': str(uuid.uuid4()), 'domain': 'api.example.test',
            'certificate_path': str(self.root / 'site.pem'), 'private_key_path': str(self.root / 'site.key'),
            'nginx_binary': '/certops-qa-fake-nginx', 'nginx_config': '/certops-qa-fake.conf',
            'reload_argv': ['/certops-qa-fake-reload']}
        self.old = self.make_pair('old')
        self.new = self.make_pair('new')
        pathlib.Path(self.config['certificate_path']).write_text(self.old['cert_pem'])
        pathlib.Path(self.config['private_key_path']).write_text(self.old['key_pem'])
        self.store = client.managed_store(self.config)

    def tearDown(self):
        self.temp.cleanup()

    def make_pair(self, name):
        cert, key = self.root / (name + '.pem'), self.root / (name + '.key')
        result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30',
            '-subj', '/CN=api.example.test', '-addext', 'subjectAltName=DNS:api.example.test',
            '-keyout', str(key), '-out', str(cert)], capture_output=True)
        self.assertEqual(result.returncode, 0)
        return {'cert_pem': cert.read_text(), 'key_pem': key.read_text(), 'fingerprint': client.fingerprint(cert)}

    def command_stub(self, fail_first_test=False):
        real = client.command
        self.commands = []
        def run(argv, data=None, code='INTERNAL_ERROR'):
            if argv[0].startswith('/certops-qa-'):
                self.commands.append(argv)
                if fail_first_test and argv[0] == '/certops-qa-fake-nginx' and len(self.commands) == 1:
                    raise client.LocalFailure(code)
                return b''
            return real(argv, data, code)
        return patch.object(client, 'command', side_effect=run)

    def test_success_switches_the_pair_and_protects_private_key(self):
        with self.command_stub(), patch.object(client, 'tls_observation', return_value=(self.new['cert_pem'], self.new['fingerprint'])):
            result = client.apply_bundle(self.config, self.store, self.new, str(uuid.uuid4()))
        self.assertEqual(result['status'], 'succeeded')
        cert, key = pathlib.Path(self.config['certificate_path']), pathlib.Path(self.config['private_key_path'])
        self.assertTrue(cert.is_symlink() and key.is_symlink())
        self.assertEqual(cert.read_text(), self.new['cert_pem'])
        self.assertEqual(key.read_text(), self.new['key_pem'])
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        originals = list((self.store / 'versions').glob('original-*'))
        self.assertEqual(len(originals), 1)
        self.assertEqual((originals[0] / 'private.key').read_text(), self.old['key_pem'])
        self.assertEqual([c[0] for c in self.commands], ['/certops-qa-fake-nginx', '/certops-qa-fake-reload'])

    def test_invalid_key_never_changes_live_files(self):
        bad = {**self.new, 'key_pem': self.old['key_pem']}
        with self.assertRaises(client.LocalFailure) as caught:
            client.apply_bundle(self.config, self.store, bad, str(uuid.uuid4()))
        self.assertEqual(caught.exception.code, 'INVALID_BUNDLE')
        self.assertFalse(pathlib.Path(self.config['certificate_path']).is_symlink())
        self.assertEqual(pathlib.Path(self.config['certificate_path']).read_text(), self.old['cert_pem'])

    def test_nginx_failure_restores_and_verifies_the_original_pair(self):
        with self.command_stub(fail_first_test=True), patch.object(client, 'tls_observation', return_value=(self.old['cert_pem'], self.old['fingerprint'])):
            with self.assertRaises(client.LocalFailure) as caught:
                client.apply_bundle(self.config, self.store, self.new, str(uuid.uuid4()))
        self.assertEqual(caught.exception.code, 'NGINX_TEST_FAILED')
        self.assertTrue(caught.exception.rolled_back)
        self.assertEqual(pathlib.Path(self.config['certificate_path']).read_text(), self.old['cert_pem'])
        self.assertEqual(pathlib.Path(self.config['private_key_path']).read_text(), self.old['key_pem'])

    def test_tls_mismatch_restores_pair_after_reload(self):
        observations = [(self.old['cert_pem'], self.old['fingerprint'])] * 9
        with self.command_stub(), patch.object(client, 'tls_observation', side_effect=observations), patch.object(client.time, 'sleep'):
            with self.assertRaises(client.LocalFailure) as caught:
                client.apply_bundle(self.config, self.store, self.new, str(uuid.uuid4()))
        self.assertEqual(caught.exception.code, 'TLS_VERIFY_FAILED')
        self.assertTrue(caught.exception.rolled_back)
        self.assertEqual(pathlib.Path(self.config['certificate_path']).read_text(), self.old['cert_pem'])


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]], verbosity=2)
