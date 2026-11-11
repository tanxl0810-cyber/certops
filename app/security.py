import hashlib
import hmac
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from datetime import timedelta
from threading import BoundedSemaphore
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request
from sqlalchemy import select, text
from .db import Audit, LoginSession, Setting, User, now, utc

passwords = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
_password_slots = BoundedSemaphore(2)


class SafeError(Exception):
    pass


def cipher():
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        raise RuntimeError('ENCRYPTION_KEY is required; back it up separately from the database')
    return Fernet(key.encode())


def seal(value):
    return cipher().encrypt(json.dumps(value, ensure_ascii=False).encode()).decode()


def unseal(value):
    return json.loads(cipher().decrypt(value.encode()))


def clean_error(error):
    value = str(error)
    value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]+-----|$)',
                   '[密钥已隐藏]', value, flags=re.S)
    value = re.sub(r'(https://open\.feishu\.cn/open-apis/bot/v2/hook/)[^\s"\']+', r'\1[已隐藏]', value)
    value = re.sub(r'(?i)\b(Bearer|Basic)\s+[^\s,"\'}]+', r'\1 [已隐藏]', value)
    names = (r'access[_-]?key[_-]?(?:secret|id)|secret[_-]?access[_-]?key|private[_-]?key|'
             r'password|passwd|passphrase|security[_-]?token|authorization|'
             r'(?:access|refresh|session|user|api|x[_-]yunxiao)[_-]?token|token|'
             r'sign[_-]?secret|client[_-]?secret|api[_-]?key|certops_session')
    # Nested JSON/repr error strings can escape both the key and value quotes.
    # Prefer hiding the rest of that log line over leaking an escaped suffix.
    value = re.sub(rf'''(?i)(\b(?:{names})\b(?:\\+["'])?\s*[:=]\s*)(?:\\+["'])[^\r\n]*''',
                   lambda match: match[1] + '[已隐藏]', value)
    value = re.sub(rf'''(?i)(\b(?:{names})\b["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,;}}\]\r\n]+)''',
                   lambda match: match[1] + '[已隐藏]', value)
    value = re.sub(r'(?i)((?:https?|postgres(?:ql)?(?:\+\w+)?|mysql(?:\+\w+)?)://[^:/@\s]+:)[^/@\s]+@',
                   lambda match: match[1] + '[已隐藏]@', value)
    return value[:700]


@contextmanager
def _password_capacity():
    # Two Argon2 operations use about 128 MiB, within the default web memory limit.
    if not _password_slots.acquire(blocking=False):
        raise HTTPException(429, '密码验证繁忙，请稍后重试')
    try:
        yield
    finally:
        _password_slots.release()


def verify_password(encoded, password):
    with _password_capacity():
        return passwords.verify(encoded, password)


def hash_password(password):
    with _password_capacity():
        return passwords.hash(password)


def _rate_lock(db, key):
    # These short transactions run before other authentication database work.
    if db.bind.dialect.name == 'postgresql':
        identity = int.from_bytes(hashlib.sha256(('rate:' + key).encode()).digest()[:8],
                                  'big', signed=True)
        db.execute(text('SELECT pg_advisory_xact_lock(:identity)'), {'identity': identity})
    elif db.bind.dialect.name == 'sqlite':
        db.execute(text('BEGIN IMMEDIATE'))
    else:
        raise RuntimeError('Authentication rate limiting requires PostgreSQL or SQLite')


def consume_rate_limit(db, key, maximum, window_seconds, message, *, timestamp=None):
    instant = time.time() if timestamp is None else timestamp
    try:
        _rate_lock(db, key)
        row = db.get(Setting, key, populate_existing=True)
        previous = row.value if row else {}
        if instant - previous.get('start', 0) >= window_seconds:
            previous = {}
        counter = {'count': previous.get('count', 0), 'start': previous.get('start', instant)}
        if counter['count'] >= maximum:
            db.commit()
            raise HTTPException(429, message)
        counter['count'] += 1
        if row:
            row.value = counter
        else:
            db.add(Setting(key=key, value=counter))
        db.commit()
    except Exception:
        db.rollback()
        raise


def reset_rate_limit(db, key):
    try:
        _rate_lock(db, key)
        row = db.get(Setting, key, populate_existing=True)
        if row:
            row.value = {'count': 0, 'start': time.time()}
        db.commit()
    except Exception:
        db.rollback()
        raise


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def allowed_origin(request):
    expected = {os.getenv('PUBLIC_URL', 'http://127.0.0.1:18090').rstrip('/'),
                'http://127.0.0.1:18090', 'http://localhost:18090'}
    origin = request.headers.get('origin', '').rstrip('/')
    if origin not in expected:
        raise HTTPException(403, '请求来源不受信任')


def authenticate(request: Request, db, allow_change=False):
    session = db.get(LoginSession, token_hash(request.cookies.get('certops_session', '')))
    if not session or utc(session.expires_at) <= now():
        raise HTTPException(401, '请登录')
    user = db.get(User, session.user_id)
    if not user:
        raise HTTPException(401, '请登录')
    from .feishu_auth import LoginError, validate_session
    try:
        validate_session(db, user)
    except LoginError as exc:
        if str(exc) == 'authorization_unavailable':
            raise HTTPException(503, '成员授权服务暂不可用，请稍后重试') from None
        from sqlalchemy import delete
        db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
        db.commit()
        raise HTTPException(401, '飞书成员授权已失效，请联系系统管理员') from None
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        allowed_origin(request)
        if not hmac.compare_digest(request.headers.get('x-csrf-token', ''), session.csrf):
            raise HTTPException(403, 'CSRF 校验失败，请刷新页面')
    if user.must_change and not allow_change:
        raise HTTPException(403, '首次登录需要修改管理员密码')
    return user, session


def bootstrap(db):
    if db.scalar(select(User).limit(1)):
        return
    path = os.getenv('ADMIN_PASSWORD_FILE')
    if path:
        with open(path, encoding='utf-8') as f:
            password = f.read().strip()
    else:
        password = os.getenv('ADMIN_PASSWORD', '').strip()
    if len(password) < 16:
        raise RuntimeError('Initial administrator password must have at least 16 characters')
    db.add(User(username='admin', password_hash=hash_password(password), must_change=True))
    db.commit()


def make_session(db, user):
    token = secrets.token_urlsafe(40)
    session = LoginSession(token_hash=token_hash(token), user_id=user.id,
                           csrf=secrets.token_urlsafe(32), expires_at=now() + timedelta(hours=12))
    db.add(session)
    return token, session


def audit(db, actor, action, resource_id='', **details):
    db.add(Audit(actor=actor, action=action, resource_id=resource_id, details=details))
