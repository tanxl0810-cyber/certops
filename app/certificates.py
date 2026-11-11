import hashlib
import ipaddress
import math
import re
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from sqlalchemy import case, func, select
from .db import Certificate, Version, now, utc
from .security import SafeError, seal
from . import lifecycle


def domain_name(value):
    value = value.strip().rstrip('.').lower()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    wild = value.startswith('*.')
    base = value[2:] if wild else value
    try:
        base = base.encode('idna').decode('ascii')
    except UnicodeError:
        raise SafeError('域名格式不正确')
    if len(base) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', base):
        raise SafeError('域名格式不正确')
    if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in base.split('.')):
        raise SafeError('域名格式不正确')
    return ('*.' if wild else '') + base


def covers(names, hostname):
    hostname = domain_name(hostname)
    for name in names:
        name = domain_name(name)
        if hostname == name or (name.startswith('*.') and hostname.endswith(name[1:])
                                 and hostname.count('.') == name.count('.')):
            return True
    return False


def cert_metadata(cert):
    names = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName) + [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return {'fingerprint': cert.fingerprint(hashes.SHA256()).hex(),
            'domains': [domain_name(n) for n in names], 'issuer': cert.issuer.rfc4514_string(),
            'serial': format(cert.serial_number, 'x'), 'not_before': cert.not_valid_before_utc,
            'not_after': cert.not_valid_after_utc}


def parse_bundle(cert_pem, key_pem=''):
    if not cert_pem or len(cert_pem) > 160000 or len(key_pem) > 32000:
        raise SafeError('证书或私钥内容为空或超过大小限制')
    try:
        chain = x509.load_pem_x509_certificates(cert_pem.encode())
        if not chain:
            raise ValueError()
        cert = chain[0]
        for index in range(len(chain) - 1):
            chain[index].verify_directly_issued_by(chain[index + 1])
        normalized = ''.join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain)
        key_normalized = ''
        if key_pem.strip():
            key = serialization.load_pem_private_key(key_pem.encode(), password=None)
            if getattr(key, 'key_size', 2048) < 2048 and key.__class__.__name__.lower().find('rsa') >= 0:
                raise SafeError('RSA 私钥长度至少为 2048 位')
            def public_bytes(k):
                return k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            if public_bytes(key.public_key()) != public_bytes(cert.public_key()):
                raise SafeError('证书与私钥不匹配')
            key_normalized = key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()
        return normalized, key_normalized, cert_metadata(cert)
    except SafeError:
        raise
    except Exception:
        raise SafeError('无法解析证书或私钥，请使用 PEM 格式；证书链按叶证书、中间证书顺序排列，私钥需先解密')


def add_version(db, certificate, cert_pem, key_pem=''):
    lifecycle.lock(db)
    lifecycle.require(db, Certificate, certificate.id)
    pem, key, meta = parse_bundle(cert_pem, key_pem)
    old = db.scalar(select(Version).where(Version.certificate_id == certificate.id,
                                        Version.fingerprint == meta['fingerprint']))
    if old:
        if key and not old.key_encrypted:
            old.key_encrypted = seal(key)
        version = old
    else:
        version = Version(certificate_id=certificate.id, cert_pem=pem,
                          key_encrypted=seal(key) if key else None, **meta)
        db.add(version)
        db.flush()
    certificate.latest_version_id = version.id
    certificate.domains = version.domains
    certificate.state = 'issued'
    return version


def import_certificate_bundle(db, name, cert_pem, key_pem=''):
    """Reuse identical leaf certificates without changing their configuration or latest version."""
    pem, key, meta = parse_bundle(cert_pem, key_pem)
    lifecycle.lock(db)
    if db.get_bind().dialect.name == 'postgresql':
        # Serialize imports of the same certificate across web processes and credentials.
        # The transaction releases this lock on both commit and rollback.
        lock_id = int.from_bytes(hashlib.sha256(('certops:import:' + meta['fingerprint']).encode()).digest()[:8],
                                 'big', signed=True)
        db.execute(select(func.pg_advisory_xact_lock(lock_id)))
    match = db.execute(select(Certificate, Version).join(Version, Version.certificate_id == Certificate.id)
        .where(Version.fingerprint == meta['fingerprint'])
        .order_by(case((Certificate.latest_version_id == Version.id, 0), else_=1),
                  Certificate.created_at, Certificate.id)).first()
    if match:
        certificate, version = match
        if lifecycle.archived(db, Certificate, certificate.id):
            raise SafeError('相同证书已在回收站，请先恢复原记录，无需重复导入')
        if key and not version.key_encrypted:
            version.key_encrypted = seal(key)
            return certificate, version, 'key_added'
        return certificate, version, 'existing'
    certificate = Certificate(name=name, source='upload')
    db.add(certificate)
    db.flush()
    version = add_version(db, certificate, pem, key)
    return certificate, version, 'imported'


def validate_deploy(version, domain):
    if not version or not version.key_encrypted:
        raise SafeError('没有可部署的证书和私钥')
    if utc(version.not_before) > now():
        raise SafeError('证书尚未生效')
    if utc(version.not_after) <= now():
        raise SafeError('证书已过期，禁止部署')
    if not covers(version.domains, domain):
        raise SafeError('证书没有覆盖目标域名')


def validate_target_deploy(version, target):
    if target.domain.startswith('*.'):
        raise SafeError('请先在目标配置中填写具体业务域名，用于部署后的 TLS 检查')
    validate_deploy(version, target.domain)
    for scope in target.config.get('required_domains', []):
        validate_deploy(version, scope)


def probe(domain, address=None, port=443, timeout=8, ca_pem=None):
    domain = domain_name(domain)
    if domain.startswith('*.'):
        raise SafeError('探测需要具体域名，不能直接探测通配符')
    address = address or domain
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((address, int(port)), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as conn:
            der = conn.getpeercert(binary_form=True)
            protocol = conn.version()
    result = cert_metadata(x509.load_der_x509_certificate(der))
    result['not_before'] = result['not_before'].isoformat()
    result['not_after'] = result['not_after'].isoformat()
    result['days_left'] = math.floor((x509.load_der_x509_certificate(der).not_valid_after_utc - now()).total_seconds() / 86400)
    result.update({'address': address, 'port': int(port), 'protocol': protocol,
                   'hostname_valid': covers(result['domains'], domain), 'trusted': False, 'trust_error': ''})
    try:
        trusted_context = ssl.create_default_context()
        if ca_pem:
            trusted_context.load_verify_locations(cadata=ca_pem)
        with socket.create_connection((address, int(port)), timeout=timeout) as raw:
            with trusted_context.wrap_socket(raw, server_hostname=domain):
                pass
        result['trusted'] = True
    except ssl.SSLError:
        result['trust_error'] = '证书信任链、域名或有效期校验失败'
    result['ok'] = result['trusted'] and result['hostname_valid'] and result['days_left'] >= 0
    return result


def version_public(version):
    if not version:
        return None
    result = {k: getattr(version, k) for k in
        ('id', 'certificate_id', 'fingerprint', 'domains', 'issuer', 'serial', 'not_before', 'not_after', 'created_at')}
    result['has_private_key'] = bool(version.key_encrypted)
    result['days_left'] = math.floor((utc(version.not_after) - now()).total_seconds() / 86400)
    return result
