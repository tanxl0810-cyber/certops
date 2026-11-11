"""Create local deployment secrets once, without printing or overwriting them."""
import argparse
import base64
import os
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit


def initialize(directory, public_url=None, port=18090):
    if not 1 <= port <= 65535:
        raise ValueError('Port must be between 1 and 65535')
    public_url = (public_url or f'http://127.0.0.1:{port}').rstrip('/')
    url = urlsplit(public_url)
    if (url.scheme not in ('http', 'https') or not url.hostname or url.path
            or url.query or url.fragment or url.username or url.password
            or not re.fullmatch(r'[A-Za-z0-9.\-:\[\]]+', url.netloc)):
        raise ValueError('PUBLIC_URL must be an HTTP(S) origin without credentials or a path')
    _ = url.port  # Reject invalid ports before writing a file.
    values = {
        'PUBLIC_URL': public_url, 'BIND_ADDRESS': '127.0.0.1', 'HTTP_PORT': str(port),
        'POSTGRES_PASSWORD': secrets.token_urlsafe(36),
        'DATABASE_PASSWORD': secrets.token_urlsafe(36),
        'ENCRYPTION_KEY': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        'ADMIN_PASSWORD': secrets.token_urlsafe(24),
        'FORWARDED_ALLOW_IPS': '127.0.0.1', 'TZ': 'Asia/Shanghai',
        'FEISHU_APP_ID': '', 'FEISHU_APP_SECRET': '', 'FEISHU_TENANT_KEY': '',
        'FEISHU_ALLOWED_OPEN_IDS': '',
    }
    path = Path(directory) / '.env'
    # O_EXCL rejects existing files and symlinks. Permissions apply before secrets are written.
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write('# Generated locally; never commit or share this file.\n')
        for key, value in values.items():
            handle.write(f'{key}={value}\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-url', help='HTTPS origin for a production installation')
    parser.add_argument('--port', type=int, default=18090, help='Loopback HTTP port')
    args = parser.parse_args()
    try:
        path = initialize(Path(__file__).resolve().parents[1], args.public_url, args.port)
    except FileExistsError:
        parser.exit(1, 'Existing .env preserved. Edit it locally; do not regenerate encryption keys.\n')
    except (OSError, ValueError):
        parser.exit(1, 'Initialization failed. Check the URL, port, directory and file permissions.\n')
    print(f'Created {path.name}. Secrets are stored only in that file; none were printed.')
    print('Read ADMIN_PASSWORD locally, then run: docker compose up -d --build')


if __name__ == '__main__':
    main()
