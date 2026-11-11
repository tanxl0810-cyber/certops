"""Restore only to an empty CertOps database, with application containers stopped."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backup', type=Path)
    parser.add_argument('--confirm-empty', action='store_true', required=True,
                        help='Acknowledge that this is a fresh recovery installation')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    backup = args.backup.resolve(strict=True)
    try:
        running = subprocess.check_output(['docker', 'compose', 'ps', '--status', 'running',
                                           '--services'], cwd=root, stderr=subprocess.PIPE).decode().splitlines()
        if 'web' in running or 'worker' in running:
            parser.exit(1, 'Stop web and worker before restoring. No database changes were made.\n')
        query = "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public';"
        count = subprocess.check_output(['docker', 'compose', 'exec', '-T', 'db', 'psql',
            '-U', 'postgres', '-d', 'certops', '-At', '-c', query], cwd=root, stderr=subprocess.PIPE).strip()
        if count != b'0':
            parser.exit(1, 'Database is not empty. Restore refused; no objects were removed.\n')
        with backup.open('rb') as handle:
            subprocess.run(['docker', 'compose', 'exec', '-T', 'db', 'pg_restore',
                '-U', 'postgres', '-d', 'certops', '--role=certops', '--no-owner', '--no-privileges',
                '--exit-on-error', '--single-transaction'], cwd=root, stdin=handle,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    except (OSError, subprocess.CalledProcessError):
        parser.exit(1, 'Restore failed; the restore transaction was not committed. Check the archive and database.\n')
    print('Restore completed. Set the original ENCRYPTION_KEY before starting web and worker.')


if __name__ == '__main__':
    main()
