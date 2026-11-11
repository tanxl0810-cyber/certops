"""Create a PostgreSQL custom-format backup without bundling deployment secrets."""
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    directory = root / 'backups'
    directory.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = directory / f'certops-{stamp}-{secrets.token_hex(3)}.dump'
    try:
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as handle:
            subprocess.run(['docker', 'compose', 'exec', '-T', 'db', 'pg_dump',
                            '-U', 'postgres', '-d', 'certops', '-Fc'],
                           cwd=root, stdout=handle, stderr=subprocess.PIPE, check=True)
        with path.open('rb') as handle:
            subprocess.run(['docker', 'compose', 'exec', '-T', 'db', 'pg_restore', '--list'],
                           cwd=root, stdin=handle, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, check=True)
    except (OSError, subprocess.CalledProcessError):
        # Leave an unsuccessful artifact distinguishable from completed backups.
        if path.exists():
            path.rename(path.with_suffix('.incomplete'))
        raise SystemExit('Backup failed. No completed backup was produced; inspect the database service.') from None
    print(f'Backup created and archive listing verified: backups/{path.name}')
    print('Store ENCRYPTION_KEY separately. An archive listing check is not a restore drill.')


if __name__ == '__main__':
    main()
