"""Feishu OAuth v2 with PKCE and an explicit, deployment-local member allowlist."""
import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

import httpx
from sqlalchemy import delete, select, text

from .db import FeishuIdentity, FeishuLoginAttempt, User, now
from .security import seal, token_hash, unseal

AUTHORIZE_URL = 'https://accounts.feishu.cn/open-apis/authen/v1/authorize'
TOKEN_URL = 'https://open.feishu.cn/open-apis/authen/v2/oauth/token'
USER_INFO_URL = 'https://open.feishu.cn/open-apis/authen/v1/user_info'
CALLBACK_PATH = '/api/auth/feishu/callback'
COOKIE_PATH = '/api/auth/feishu'
COOKIE_NAME = 'certops_feishu_state'
TTL = 300


class LoginError(Exception):
    """Contains a fixed diagnostic reason, never an upstream body or credential."""


@dataclass(frozen=True)
class Config:
    app_id: str
    secret: str = field(repr=False)
    tenant_key: str
    public_url: str
    allowed_open_ids: tuple[str, ...] = field(repr=False)

    @property
    def callback_url(self):
        return self.public_url + CALLBACK_PATH

    @property
    def fingerprint(self):
        return token_hash(json.dumps([self.app_id, self.secret, self.tenant_key,
                                     self.public_url, self.allowed_open_ids]))


def config():
    app_id = os.getenv('FEISHU_APP_ID', '').strip()
    secret = os.getenv('FEISHU_APP_SECRET', '').strip()
    tenant = os.getenv('FEISHU_TENANT_KEY', '').strip()
    public = os.getenv('PUBLIC_URL', '').rstrip('/')
    members = tuple(sorted(set(value.strip() for value in
        os.getenv('FEISHU_ALLOWED_OPEN_IDS', '').split(',') if value.strip())))
    url = urlsplit(public)
    if not (app_id and secret and tenant and members and all(len(value) <= 128 for value in members)
            and url.scheme == 'https' and url.hostname
            and url.path == '' and not url.query and not url.fragment and not url.username):
        return None
    return Config(app_id, secret, tenant, public, members)


def authorized_member(cfg, open_id, tenant_key):
    if not isinstance(open_id, str) or not 1 <= len(open_id) <= 128:
        raise LoginError('identity_invalid')
    if not isinstance(tenant_key, str) or not hmac.compare_digest(tenant_key.encode(), cfg.tenant_key.encode()):
        raise LoginError('tenant_denied')
    if open_id not in cfg.allowed_open_ids:
        raise LoginError('member_denied')
    return {'open_id': open_id}


def start(db, cfg):
    state, browser, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    db.execute(delete(FeishuLoginAttempt).where(FeishuLoginAttempt.expires_at <= now()))
    db.add(FeishuLoginAttempt(state_hash=token_hash(state), browser_hash=token_hash(browser),
        verifier_encrypted=seal(verifier), config_hash=cfg.fingerprint,
        expires_at=now() + timedelta(seconds=TTL)))
    db.commit()
    return AUTHORIZE_URL + '?' + urlencode({'client_id': cfg.app_id, 'response_type': 'code',
        'redirect_uri': cfg.callback_url, 'state': state, 'code_challenge': challenge,
        'code_challenge_method': 'S256'}), browser


def consume(db, cfg, state, browser):
    if not state or not browser or len(state) > 128 or len(browser) > 128:
        raise LoginError('state_invalid')
    encrypted = db.scalar(delete(FeishuLoginAttempt).where(
        FeishuLoginAttempt.state_hash == token_hash(state),
        FeishuLoginAttempt.browser_hash == token_hash(browser),
        FeishuLoginAttempt.config_hash == cfg.fingerprint,
        FeishuLoginAttempt.expires_at > now()).returning(FeishuLoginAttempt.verifier_encrypted))
    db.commit()  # Consume before the first network request, including when exchange fails.
    if not encrypted:
        raise LoginError('state_invalid')
    return unseal(encrypted)


def exchange(cfg, code, verifier):
    if not code or len(code) > 4096:
        raise LoginError('code_invalid')
    try:
        with httpx.Client(timeout=15, follow_redirects=False) as client:
            response = client.post(TOKEN_URL, json={'grant_type': 'authorization_code',
                'client_id': cfg.app_id, 'client_secret': cfg.secret, 'code': code,
                'code_verifier': verifier, 'redirect_uri': cfg.callback_url})
            if response.status_code != 200:
                raise LoginError('token_failed')
            result = response.json()
            if not isinstance(result, dict) or result.get('code') != 0 or result.get('error'):
                raise LoginError('token_failed')
            token = result.get('access_token')
            if not isinstance(token, str) or not token:
                raise LoginError('token_failed')
            response = client.get(USER_INFO_URL, headers={'Authorization': 'Bearer ' + token})
            if response.status_code != 200:
                raise LoginError('userinfo_failed')
            result = response.json()
            if not isinstance(result, dict) or result.get('code') != 0 or not isinstance(result.get('data'), dict):
                raise LoginError('userinfo_failed')
            info = result['data']
    except LoginError:
        raise
    except Exception:
        raise LoginError('upstream_unavailable') from None
    authorized_member(cfg, info.get('open_id'), info.get('tenant_key'))
    name = info.get('name')
    return info['open_id'], info['tenant_key'], name[:128] if isinstance(name, str) and name else '飞书用户'


def provision(db, cfg, open_id, tenant_key, name):
    # Serialize first login for the same subject, across all web processes.
    username = 'feishu:' + token_hash(cfg.app_id + '\0' + open_id)[:48]
    if db.bind.dialect.name == 'postgresql':
        lock_id = int.from_bytes(hashlib.sha256(username.encode()).digest()[:8], 'big', signed=True)
        db.execute(text('SELECT pg_advisory_xact_lock(:identity)'), {'identity': lock_id})
    identity = db.scalar(select(FeishuIdentity).where(FeishuIdentity.app_id == cfg.app_id,
                                                   FeishuIdentity.open_id == open_id))
    if identity:
        if not hmac.compare_digest(identity.tenant_key, tenant_key):
            raise LoginError('tenant_denied')
        identity.display_name = name
        return db.get(User, identity.user_id)
    user = User(username=username, password_hash='!feishu-only', must_change=False)
    db.add(user)
    db.flush()
    db.add(FeishuIdentity(user_id=user.id, app_id=cfg.app_id, open_id=open_id,
                          tenant_key=tenant_key, display_name=name))
    db.flush()
    return user


def validate_session(db, user):
    identity = db.get(FeishuIdentity, user.id)
    if not identity:
        return None
    cfg = config()
    if not cfg or identity.app_id != cfg.app_id:
        raise LoginError('member_denied')
    authorized_member(cfg, identity.open_id, identity.tenant_key)
    return identity


def public_user(db, user, session):
    identity = db.get(FeishuIdentity, user.id)
    return {'username': user.username, 'display_name': identity.display_name if identity else user.username,
            'provider': 'feishu' if identity else 'password', 'csrf': session.csrf,
            'must_change': user.must_change}
