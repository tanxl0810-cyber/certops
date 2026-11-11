"""Protect fresh-install secrets and source-only release boundaries."""
import base64
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


def load_tool(name, filename):
    path = Path(__file__).resolve().parents[1] / 'ops' / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


initialize = load_tool('release_init', 'init.py').initialize
check = load_tool('release_check', 'check-release.py')


class ReleaseTests(unittest.TestCase):
    def test_secrets_are_unique_and_rerun_preserves_encryption_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = initialize(directory)
            original = path.read_bytes()
            values = dict(line.split('=', 1) for line in original.decode().splitlines() if '=' in line)
            self.assertEqual(len(base64.urlsafe_b64decode(values['ENCRYPTION_KEY'])), 32)
            self.assertEqual(len({values[key] for key in ('DATABASE_PASSWORD', 'POSTGRES_PASSWORD', 'ADMIN_PASSWORD')}), 3)
            self.assertGreaterEqual(len(values['ADMIN_PASSWORD']), 16)
            with self.assertRaises(FileExistsError):
                initialize(directory)
            self.assertEqual(path.read_bytes(), original)
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_invalid_origin_never_creates_configuration(self):
        for value in ('https://example.com/path', 'https://user:password@example.com',
                      'https://example.com?x=y', 'https://example.com\nBAD=value'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    initialize(directory, value)
                self.assertFalse((Path(directory) / '.env').exists())

    def test_package_candidates_exclude_local_secrets_history_and_builds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('README.md', '.env.example', '.env', '.env.feishu', '.git/config',
                         'private/recovery.json', 'backups/cert.dump', 'ui/src/App.vue',
                         'ui/node_modules/package/index.js', 'app/static/assets/bundle.js',
                         'docs/private.key', 'docs/screenshot.png', 'dist/previous.zip'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture', encoding='utf-8')
            self.assertEqual({p.relative_to(root).as_posix() for p in check.release_files(root)},
                             {'README.md', '.env.example', 'ui/src/App.vue'})

    def test_scanner_reports_locations_without_the_matched_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = 'LTAI' + 'a' * 24
            (root / 'README.md').write_text(fake, encoding='utf-8')
            result = '\n'.join(check.findings(root))
            self.assertIn('cloud-access-key', result)
            self.assertNotIn(fake, result)

    def test_only_approved_plain_png_documentation_images_can_be_packaged(self):
        image = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aVOsAAAAASUVORK5CYII=')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / 'docs/images/overview.png'
            approved.parent.mkdir(parents=True)
            approved.write_bytes(image)
            (approved.parent / 'unreviewed.png').write_bytes(image)
            self.assertEqual(check.release_files(root), [approved])
            self.assertEqual(check.findings(root), [])
            approved.write_bytes(image + b'private appended metadata')
            self.assertIn('unapproved metadata', '\n'.join(check.findings(root)))

    def test_replacing_the_authorized_contact_card_requires_a_new_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / 'docs/images/wechat-contact.jpg'
            approved.parent.mkdir(parents=True)
            approved.write_bytes(b'changed contact image')
            (approved.parent / 'unreviewed-contact.jpg').write_bytes(b'private image')
            self.assertEqual(check.release_files(root), [approved])
            self.assertIn('unreviewed image content', '\n'.join(check.findings(root)))


if __name__ == '__main__':
    unittest.main()
