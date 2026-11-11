"""Read-only checks of health, frontend assets, and anonymous access protection."""
import argparse
import re
from urllib.parse import urlsplit
import httpx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='http://127.0.0.1:18090')
    args = parser.parse_args()
    base = args.base.rstrip('/')
    url = urlsplit(base)
    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.path or url.query or url.fragment:
        parser.error('--base must be an HTTP(S) origin')
    with httpx.Client(base_url=base, timeout=15, trust_env=False, follow_redirects=False) as client:
        response = client.get('/healthz')
        response.raise_for_status()
        assert response.json()['service'] == 'certops'
        response = client.get('/')
        response.raise_for_status()
        assert '域名证书控制台' in response.text
        for path in re.findall(r'(?:src|href)="(/assets/[^"\s]+)"', response.text):
            client.get(path).raise_for_status()
        assert client.get('/api/credentials').status_code == 401
        assert client.get('/api/dashboard').status_code == 401
        response = client.get('/api/auth/options')
        response.raise_for_status()
        assert isinstance(response.json()['feishu'], bool)
    print('PASS health, frontend assets and anonymous access protection')


if __name__ == '__main__':
    main()
