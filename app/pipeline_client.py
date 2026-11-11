#!/usr/bin/env python3
"""One-shot host deployment client. Python stdlib + OpenSSL; no listening service."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class LocalFailure(Exception):
    def __init__(self, code, rolled_back=False):
        self.code, self.rolled_back = code, rolled_back


def command(argv, data=None, code='INTERNAL_ERROR'):
    try:
        result = subprocess.run(argv, input=data, capture_output=True, timeout=35)
    except (OSError, subprocess.TimeoutExpired):
        raise LocalFailure(code) from None
    if result.returncode:
        raise LocalFailure(code)
    return result.stdout


def durable_write(path, content, mode=0o600):
    path = pathlib.Path(path)
    temp = path.with_name(path.name + '.tmp-' + secrets.token_hex(8))
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content if isinstance(content, bytes) else content.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temp), str(path))
        os.chmod(str(path), mode)
    finally:
        if temp.exists():
            temp.unlink()


def atomic_link(path, destination):
    path = pathlib.Path(path)
    temp = path.with_name(path.name + '.tmp-' + secrets.token_hex(8))
    try:
        os.symlink(str(destination), str(temp))
        os.replace(str(temp), str(path))
        fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temp.is_symlink():
            temp.unlink()


def fingerprint(path):
    text = command(['openssl', 'x509', '-in', str(path), '-noout', '-fingerprint', '-sha256'],
                   code='INVALID_BUNDLE').decode()
    value = text.split('=', 1)[-1].strip().replace(':', '').lower()
    if not re.fullmatch(r'[a-f0-9]{64}', value):
        raise LocalFailure('INVALID_BUNDLE')
    return value


def verify_pair(cert, key, domain):
    host_check = command(['openssl', 'x509', '-in', str(cert), '-noout', '-checkhost', domain], code='INVALID_BUNDLE')
    if b'does NOT match' in host_check:
        raise LocalFailure('INVALID_BUNDLE')
    command(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '0'], code='INVALID_BUNDLE')
    public_pem = command(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'], code='INVALID_BUNDLE')
    public = command(['openssl', 'pkey', '-pubin', '-outform', 'DER'], public_pem, code='INVALID_BUNDLE')
    key_public = command(['openssl', 'pkey', '-in', str(key), '-passin', 'pass:', '-pubout', '-outform', 'DER'],
                         code='INVALID_BUNDLE')
    if public != key_public:
        raise LocalFailure('INVALID_BUNDLE')


def tls_observation(config):
    context = ssl.create_default_context(cafile=config.get('ca_file') or None)
    with socket.create_connection((config.get('probe_address', '127.0.0.1'), int(config.get('probe_port', 443))), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=config['domain']) as conn:
            der = conn.getpeercert(binary_form=True)
    return ssl.DER_cert_to_PEM_cert(der), hashlib.sha256(der).hexdigest()


def health_check(config):
    url = config.get('health_url')
    if not url:
        return True
    if urllib.parse.urlsplit(url).scheme != 'https':
        raise LocalFailure('LOCAL_CONFIG_INVALID')
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        with opener.open(url, timeout=8) as response:
            if not 200 <= response.status < 300:
                raise LocalFailure('HEALTH_FAILED')
    except urllib.error.HTTPError as error:
        error.close()
        raise LocalFailure('HEALTH_FAILED') from None
    except Exception:
        raise LocalFailure('HEALTH_FAILED') from None
    return True


def managed_store(config):
    cert, key = pathlib.Path(config['certificate_path']), pathlib.Path(config['private_key_path'])
    if not cert.is_absolute() or not key.is_absolute() or cert == key or cert.parent != key.parent:
        raise LocalFailure('LOCAL_CONFIG_INVALID')
    store = cert.parent / ('.certops-' + str(uuid.UUID(config['target_id'])))
    if store.is_symlink():
        raise LocalFailure('LOCAL_CONFIG_INVALID')
    store.mkdir(mode=0o700, exist_ok=True)
    os.chmod(str(store), 0o700)
    (store / 'versions').mkdir(mode=0o700, exist_ok=True)
    (store / 'jobs').mkdir(mode=0o700, exist_ok=True)
    return store


def stage_pair(store, name, cert_pem, key_pem):
    directory = store / 'versions' / name
    if directory.exists():
        raise LocalFailure('LOCAL_CONFIG_INVALID')
    directory.mkdir(mode=0o700)
    durable_write(directory / 'fullchain.pem', cert_pem, 0o644)
    durable_write(directory / 'private.key', key_pem, 0o600)
    return directory


def ensure_managed(config, store):
    """First migrate both original paths to an identical old pair, then use one atomic pointer."""
    cert, key = pathlib.Path(config['certificate_path']), pathlib.Path(config['private_key_path'])
    current = store / 'current'
    if not current.is_symlink():
        if current.exists() or cert.is_symlink() or key.is_symlink() or not cert.is_file() or not key.is_file():
            raise LocalFailure('LOCAL_CONFIG_INVALID')
        old = stage_pair(store, 'original-' + secrets.token_hex(12), cert.read_bytes(), key.read_bytes())
        atomic_link(current, pathlib.Path('versions') / old.name)
    resolved = current.resolve(strict=True)
    if resolved.parent != (store / 'versions').resolve() or not (resolved / 'fullchain.pem').is_file() or not (resolved / 'private.key').is_file():
        raise LocalFailure('LOCAL_CONFIG_INVALID')
    for path, leaf in ((cert, 'fullchain.pem'), (key, 'private.key')):
        expected = current / leaf
        if path.is_symlink():
            if os.readlink(str(path)) != str(expected):
                raise LocalFailure('LOCAL_CONFIG_INVALID')
        else:
            # An interrupted initial migration can be resumed only if the original data still matches.
            if not path.is_file() or path.read_bytes() != (resolved / leaf).read_bytes():
                raise LocalFailure('LOCAL_CONFIG_INVALID')
            atomic_link(path, expected)
    return pathlib.Path(os.readlink(str(current)))


def apply_bundle(config, store, bundle, attempt_id):
    if len(bundle.get('cert_pem', '')) > 160000 or len(bundle.get('key_pem', '')) > 32000:
        raise LocalFailure('INVALID_BUNDLE')
    generation = 'generation-' + str(uuid.UUID(attempt_id)) + '-' + secrets.token_hex(6)
    staged = stage_pair(store, generation, bundle['cert_pem'], bundle['key_pem'])
    verify_pair(staged / 'fullchain.pem', staged / 'private.key', config['domain'])
    if fingerprint(staged / 'fullchain.pem') != bundle['fingerprint']:
        raise LocalFailure('INVALID_BUNDLE')
    nginx = [config.get('nginx_binary', '/usr/sbin/nginx'), '-t', '-c', config.get('nginx_config', '/etc/nginx/nginx.conf')]
    reload_argv = config.get('reload_argv', ['systemctl', 'reload', 'nginx'])
    if not isinstance(reload_argv, list) or not reload_argv or not all(isinstance(x, str) and x for x in reload_argv):
        raise LocalFailure('LOCAL_CONFIG_INVALID')
    old = ensure_managed(config, store)
    atomic_link(store / 'current', pathlib.Path('versions') / staged.name)
    try:
        command(nginx, code='NGINX_TEST_FAILED')
        command(reload_argv, code='RELOAD_FAILED')
        certificate_pem = None
        for count in range(8):
            try:
                pem, actual = tls_observation(config)
                if actual == bundle['fingerprint']:
                    certificate_pem = pem
                    break
            except (OSError, ssl.SSLError):
                pass
            time.sleep(1)
        if not certificate_pem:
            raise LocalFailure('TLS_VERIFY_FAILED')
        health_check(config)
        return {'status': 'succeeded', 'certificate_pem': certificate_pem, 'trusted': True,
                'nginx_test_ok': True, 'nginx_reload_ok': True, 'health_ok': True,
                'rolled_back': False, 'error_code': ''}
    except Exception as error:
        atomic_link(store / 'current', old)
        rollback_ok = False
        try:
            command(nginx, code='NGINX_TEST_FAILED')
            command(reload_argv, code='RELOAD_FAILED')
            expected_old = fingerprint((store / 'current').resolve() / 'fullchain.pem')
            for count in range(8):
                try:
                    _, actual_old = tls_observation(config)
                    if actual_old == expected_old:
                        rollback_ok = True
                        break
                except (OSError, ssl.SSLError):
                    pass
                time.sleep(1)
        except Exception:
            pass
        code = error.code if isinstance(error, LocalFailure) else 'INTERNAL_ERROR'
        raise LocalFailure(code, rolled_back=rollback_ok) from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, config, job_id, attempt_id):
        parsed = urllib.parse.urlsplit(config['base_url'])
        if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise LocalFailure('LOCAL_CONFIG_INVALID')
        self.base = config['base_url'].rstrip('/') + '/api/pipeline/jobs/' + str(uuid.UUID(job_id))
        self.config = config
        self.body = {'attempt_id': str(uuid.UUID(attempt_id)), 'machine_id': config['machine_id'],
                     'pipeline_id': str(config['pipeline_id'])}
        context = ssl.create_default_context(cafile=config.get('controller_ca_file') or None)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def post(self, action, extra=None):
        body = {**self.body, **(extra or {})}
        encoded = json.dumps(body).encode()
        for count in range(3):
            request = urllib.request.Request(self.base + '/' + action, data=encoded, method='POST',
                headers={'Authorization': 'Bearer ' + self.config['token'], 'Content-Type': 'application/json'})
            try:
                with self.opener.open(request, timeout=15) as response:
                    data = response.read(220000)
                    return json.loads(data)
            except (urllib.error.URLError, ValueError, OSError):
                if count == 2:
                    raise LocalFailure('DOWNLOAD_FAILED') from None
                time.sleep(count + 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/certops/pipeline.json')
    parser.add_argument('--job-id', default=os.getenv('CERTOPS_JOB_ID'))
    parser.add_argument('--attempt-id', default=os.getenv('CERTOPS_ATTEMPT_ID'))
    args = parser.parse_args()
    if not args.job_id or not args.attempt_id:
        print('CertOps: missing task identifiers; no files changed', file=sys.stderr)
        return 2
    try:
        if os.geteuid() != 0:
            raise LocalFailure('LOCAL_CONFIG_INVALID')
        path = pathlib.Path(args.config)
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077 or path.is_symlink():
            raise LocalFailure('LOCAL_CONFIG_INVALID')
        config = json.loads(path.read_text())
        store = managed_store(config)
        import fcntl
        with (store / 'deployment.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            client = Client(config, args.job_id, args.attempt_id)
            manifest = client.post('claim')
            if manifest.get('complete'):
                print('CertOps: task already reported')
                return 0 if manifest.get('status') == 'succeeded' else 1
            if (manifest['target_id'] != config['target_id'] or manifest['domain'] != config['domain'] or
                manifest['certificate_path'] != config['certificate_path'] or
                manifest['private_key_path'] != config['private_key_path']):
                raise LocalFailure('LOCAL_CONFIG_INVALID')
            cache = store / 'jobs' / (str(uuid.UUID(args.job_id)) + '-' + str(uuid.UUID(args.attempt_id)) + '.json')
            if cache.is_file():
                report = json.loads(cache.read_text())
                if report['status'] == 'succeeded':
                    _, actual = tls_observation(config)
                    if actual != hashlib.sha256(ssl.PEM_cert_to_DER_cert(report['certificate_pem'])).hexdigest():
                        raise LocalFailure('TLS_VERIFY_FAILED')
            else:
                try:
                    if manifest['operation'] == 'probe':
                        pem, _ = tls_observation(config)
                        health_check(config)
                        report = {'status': 'succeeded', 'certificate_pem': pem, 'trusted': True,
                                  'health_ok': True, 'error_code': ''}
                    else:
                        bundle = client.post('bundle')
                        if bundle['version_id'] != manifest['version_id'] or bundle['fingerprint'] != manifest['fingerprint']:
                            raise LocalFailure('INVALID_BUNDLE')
                        report = apply_bundle(config, store, bundle, args.attempt_id)
                except Exception as error:
                    report = {'status': 'failed', 'error_code': error.code if isinstance(error, LocalFailure) else 'INTERNAL_ERROR',
                              'rolled_back': getattr(error, 'rolled_back', False)}
                durable_write(cache, json.dumps(report))
            client.post('report', report)
            print('CertOps: ' + report['status'] + '; result acknowledged')
            return 0 if report['status'] == 'succeeded' else 1
    except Exception as error:
        code = error.code if isinstance(error, LocalFailure) else 'INTERNAL_ERROR'
        print('CertOps: ' + code + '; inspect the console task', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
