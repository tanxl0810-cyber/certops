import base64
import hashlib
import hmac
import io
import shlex
import socket
import posixpath
from contextlib import contextmanager
import paramiko
from .db import Credential
from .security import SafeError, unseal


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


class PinPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, pin):
        self.pin = pin

    def missing_host_key(self, client, hostname, key):
        if not hmac.compare_digest(fingerprint(key), self.pin):
            raise SafeError('SSH 主机指纹不匹配，请核实目标主机；未发送登录凭据')
        client.get_host_keys().add(hostname, key.get_name(), key)


def private_key(secret):
    value = secret.get('private_key', '')
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(value), password=secret.get('passphrase') or None)
        except (paramiko.SSHException, ValueError):
            continue
    raise SafeError('无法读取 SSH 私钥，请核对 OpenSSH/PEM 格式及口令')


@contextmanager
def connect(db, secret, depth=0):
    if depth > 2:
        raise SafeError('SSH 跳板链过深或存在循环')
    client = paramiko.SSHClient()
    pin = secret.get('host_key', '')
    if not pin.startswith('SHA256:'):
        raise SafeError('请先获取并保存 SSH 主机 SHA256 指纹')
    client.set_missing_host_key_policy(PinPolicy(pin))
    jump_id = secret.get('jump_credential_id')
    try:
        if jump_id:
            from . import lifecycle
            lifecycle.require(db, Credential, jump_id)
            row = db.get(Credential, jump_id)
            if not row or row.kind != 'ssh':
                raise SafeError('SSH 跳板机凭据不存在')
            with connect(db, unseal(row.encrypted), depth + 1) as jump:
                channel = jump.get_transport().open_channel('direct-tcpip',
                    (secret['host'], int(secret.get('port', 22))), ('127.0.0.1', 0), timeout=15)
                client.connect(secret['host'], port=int(secret.get('port', 22)),
                    username=secret.get('username', 'root'), pkey=private_key(secret),
                    sock=channel, timeout=15, banner_timeout=15, auth_timeout=15,
                    look_for_keys=False, allow_agent=False)
                yield client
        else:
            client.connect(secret['host'], port=int(secret.get('port', 22)),
                username=secret.get('username', 'root'), pkey=private_key(secret),
                timeout=15, banner_timeout=15, auth_timeout=15, look_for_keys=False, allow_agent=False)
            yield client
    except SafeError:
        raise
    except (paramiko.SSHException, OSError):
        raise SafeError('SSH 连接或执行失败，请核对网络、密钥、主机指纹及账号权限') from None
    finally:
        client.close()


def get_fingerprint(host, port):
    with socket.create_connection((host, int(port)), timeout=8) as sock:
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=10)
            return fingerprint(transport.get_remote_server_key())
        finally:
            transport.close()


def command(client, text, timeout=60):
    _, stdout, stderr = client.exec_command(text, timeout=timeout)
    output = stdout.read(32768).decode(errors='replace')
    error = stderr.read(32768).decode(errors='replace')
    code = stdout.channel.recv_exit_status()
    if code:
        raise SafeError(f'远程命令失败（退出码 {code}），{(error or output)[-600:]}')
    return output


def check_path(path):
    if not isinstance(path, str) or not path.startswith('/') or '\n' in path or '\x00' in path:
        raise SafeError('证书路径必须是绝对路径')
    if posixpath.normpath(path) != path or path in ('/', '/etc', '/etc/nginx'):
        raise SafeError('证书路径不正确')
    if not path.endswith(('.pem', '.crt', '.cer', '.key')):
        raise SafeError('证书路径应以 .pem、.crt、.cer 或 .key 结尾')
    return path


def deployment_script(config, job_id):
    cert = check_path(config['certificate_path'])
    key = check_path(config['private_key_path'])
    if cert == key:
        raise SafeError('证书和私钥路径必须不同')
    test = config.get('test_command', 'nginx -t')
    reload = config.get('reload_command', 'systemctl reload nginx')
    if any('\n' in value or '\x00' in value or len(value) > 1000 for value in (test, reload)):
        raise SafeError('检查与重载命令必须是单行命令')
    q = shlex.quote
    return f'''set -eu
cert={q(cert)}
key={q(key)}
cert_tmp={q(cert + '.certops-' + job_id + '.tmp')}
key_tmp={q(key + '.certops-' + job_id + '.tmp')}
cert_backup={q(cert + '.certops-' + job_id + '.bak')}
key_backup={q(key + '.certops-' + job_id + '.bak')}
had_cert=0
had_key=0
test -f "$cert" && had_cert=1 || true
test -f "$key" && had_key=1 || true
test "$had_cert" = "$had_key" || {{ echo '证书与私钥现状不一致，已停止'; exit 21; }}
if [ "$had_cert" = 1 ]; then
  test -f "$cert_backup" || cp -p -- "$cert" "$cert_backup"
  test -f "$key_backup" || cp -p -- "$key" "$key_backup"
fi
rollback() {{
  code=$?
  trap - EXIT
  if [ "$code" != 0 ]; then
    if [ "$had_cert" = 1 ]; then
      cp -p -- "$cert_backup" "$cert"
      cp -p -- "$key_backup" "$key"
      if {test} >/dev/null 2>&1 && {reload} >/dev/null 2>&1; then
        echo '部署失败，已恢复原文件并重载' >&2
      else
        echo '部署失败，原文件已恢复，但回退重载失败，请立即检查 Nginx' >&2
      fi
    else
      rm -f -- "$cert" "$key"
      echo '首次部署失败，已移除本次证书文件' >&2
    fi
  fi
  rm -f -- "$cert_tmp" "$key_tmp"
  exit "$code"
}}
trap rollback EXIT
mv -f -- "$cert_tmp" "$cert"
mv -f -- "$key_tmp" "$key"
chmod 600 "$key"
{test}
{reload}
echo 'nginx_reload_ok'
'''


def deploy(db, target, secret, cert_pem, key_pem, job_id):
    config = target.config
    script = deployment_script(config, job_id)
    with connect(db, secret) as client:
        with client.open_sftp() as sftp:
            for path, value, mode in ((config['certificate_path'], cert_pem, 0o644),
                                      (config['private_key_path'], key_pem, 0o600)):
                parent = posixpath.dirname(path)
                # Directory creation is explicit and bounded by the configured certificate paths.
                command(client, 'mkdir -p -- ' + shlex.quote(parent))
                temp = path + '.certops-' + job_id + '.tmp'
                with sftp.file(temp, 'w') as f:
                    f.chmod(0o600)
                    f.write(value)
                sftp.chmod(temp, mode)
        output = command(client, 'bash -c ' + shlex.quote(script), timeout=90)
    return {'nginx_reload': 'ok', 'backup_suffix': '.certops-' + job_id + '.bak'}
