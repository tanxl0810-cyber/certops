import json
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from datetime import timedelta
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from typing import Annotated, Literal
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select, text
from .db import (Alert, Audit, Certificate, Credential, FeishuIdentity, Job, LoginSession, Session,
                 ResourceArchive, Setting, Target, TargetExclusion, User, Version, get_db, init_db, now, setting, set_setting, utc)
from .security import (SafeError, allowed_origin, audit, authenticate, bootstrap, cipher,
                       clean_error, consume_rate_limit, hash_password, make_session,
                       reset_rate_limit, seal, unseal, verify_password)
from .http_limits import RequestBodyLimit
from .certificates import add_version, covers, domain_name, import_certificate_bundle, validate_target_deploy, version_public
from .cloud import Aliyun
from .catalog import TARGETS, ISSUER_V1, ISSUER_V2
from .worker import ACTIVE, auto_deploy, enqueue
from .sshdeploy import check_path, connect, command, get_fingerprint
from .notifications import send_feishu
from . import feishu_auth
from .yunxiao import Yunxiao
from . import pipeline
from . import lifecycle
from . import exclusions
from . import relationships


class OAuthAccessFilter(logging.Filter):
    def filter(self, record):
        # Uvicorn normally includes the OAuth code in the access log's query string.
        if isinstance(record.args, tuple) and len(record.args) == 5:
            args = list(record.args)
            if isinstance(args[2], str) and args[2].startswith('/api/auth/feishu/'):
                args[2] = args[2].split('?', 1)[0]
                record.args = tuple(args)
        return True


logging.getLogger('uvicorn.access').addFilter(OAuthAccessFilter())


@asynccontextmanager
async def lifespan(app):
    cipher()
    init_db()
    with Session() as db:
        bootstrap(db)
    yield


app = FastAPI(title='域名证书控制台', version='1.6.0', docs_url=None, redoc_url=None,
              openapi_url=None, lifespan=lifespan)
Db = Annotated[object, Depends(get_db)]
app.include_router(pipeline.router)
app.add_middleware(RequestBodyLimit, max_bytes=400000)


@app.middleware('http')
async def headers(request, call_next):
    response = await call_next(request)
    response.headers.update({'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer' if request.url.path.startswith('/api/auth/feishu/') else 'same-origin', 'Cache-Control': 'no-store',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
    public = urlsplit(os.getenv('PUBLIC_URL', ''))
    if request.url.scheme == 'https' or (public.scheme == 'https' and request.url.hostname == public.hostname):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response


@app.exception_handler(SafeError)
async def safe_error(request, exc):
    return JSONResponse({'detail': clean_error(exc)}, status_code=400)


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid')


class LoginInput(Input):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


@app.get('/healthz')
def health(db: Db):
    db.execute(text('SELECT 1'))
    return {'status': 'ok', 'service': 'certops', 'version': '1.6.0'}


@app.get('/api/auth/options')
def auth_options():
    cfg = feishu_auth.config()
    return {'feishu': bool(cfg), 'login_url': cfg.public_url + '/api/auth/feishu/login' if cfg else None}


@app.get('/api/auth/feishu/login')
def feishu_login(request: Request, db: Db):
    cfg = feishu_auth.config()
    if not cfg:
        raise HTTPException(503, '飞书登录尚未配置')
    # PUBLIC_URL, rather than a proxy's rewritten Host, determines every OAuth URL.
    # A local SSH tunnel should start the flow on the public, HTTPS cookie origin.
    if request.url.hostname in ('127.0.0.1', 'localhost', '::1'):
        return RedirectResponse(cfg.public_url + '/api/auth/feishu/login', status_code=303)
    key = 'feishu-limit:' + feishu_auth.token_hash(request.client.host if request.client else '')
    consume_rate_limit(db, key, 20, 300, '登录尝试过于频繁，请稍后重试')
    location, browser = feishu_auth.start(db, cfg)
    response = RedirectResponse(location, status_code=303)
    response.set_cookie(feishu_auth.COOKIE_NAME, browser, httponly=True, secure=True,
                        samesite='lax', max_age=feishu_auth.TTL, path=feishu_auth.COOKIE_PATH)
    return response


@app.get('/api/auth/feishu/callback')
def feishu_callback(request: Request, db: Db):
    cfg = feishu_auth.config()
    try:
        if not cfg:
            raise feishu_auth.LoginError('not_configured')
        verifier = feishu_auth.consume(db, cfg, request.query_params.get('state', ''),
                                      request.cookies.get(feishu_auth.COOKIE_NAME, ''))
        if request.query_params.get('error'):
            raise feishu_auth.LoginError('cancelled')
        open_id, tenant, name = feishu_auth.exchange(cfg, request.query_params.get('code', ''), verifier)
        user = feishu_auth.provision(db, cfg, open_id, tenant, name)
        token, session = make_session(db, user)
        audit(db, user.username, 'feishu_login', display_name=name)
        db.commit()
        response = RedirectResponse('/', status_code=303)
        response.set_cookie('certops_session', token, httponly=True, secure=True,
                            samesite='lax', max_age=43200, path='/')
    except feishu_auth.LoginError as exc:
        db.rollback()
        audit(db, 'anonymous', 'feishu_login_failed', reason=str(exc))
        db.commit()
        response = RedirectResponse('/?feishu_error=' + str(exc), status_code=303)
    response.delete_cookie(feishu_auth.COOKIE_NAME, path=feishu_auth.COOKIE_PATH,
                           httponly=True, secure=True, samesite='lax')
    return response


@app.post('/api/login')
def login(data: LoginInput, request: Request, db: Db):
    allowed_origin(request)
    from .security import token_hash
    address = request.client.host if request.client else ''
    address_key = 'login-ip-limit:' + token_hash(address)
    key = 'login-limit:' + token_hash(address + ':' + data.username)
    consume_rate_limit(db, address_key, 30, 900, '登录尝试过于频繁，请 15 分钟后重试')
    consume_rate_limit(db, key, 10, 900, '登录失败次数过多，请 15 分钟后重试')
    user = db.scalar(select(User).where(User.username == data.username))
    valid = False
    if user and not db.get(FeishuIdentity, user.id):
        try:
            valid = verify_password(user.password_hash, data.password)
        except HTTPException:
            raise
        except Exception:
            pass
    if not valid:
        raise HTTPException(401, '账号或密码不正确')
    reset_rate_limit(db, key)
    reset_rate_limit(db, address_key)
    token, session = make_session(db, user)
    audit(db, user.username, 'login')
    db.commit()
    response = JSONResponse(feishu_auth.public_user(db, user, session))
    public = urlsplit(os.getenv('PUBLIC_URL', ''))
    secure = request.url.scheme == 'https' or (public.scheme == 'https' and request.url.hostname == public.hostname)
    response.set_cookie('certops_session', token, httponly=True, secure=secure,
                        samesite='strict', max_age=43200, path='/')
    return response


@app.get('/api/session')
def session(request: Request, db: Db):
    user, session = authenticate(request, db, allow_change=True)
    return feishu_auth.public_user(db, user, session)


@app.post('/api/logout')
def logout(request: Request, db: Db):
    user, session = authenticate(request, db, allow_change=True)
    db.delete(session)
    db.commit()
    response = JSONResponse({'ok': True})
    response.delete_cookie('certops_session', path='/')
    return response


class PasswordInput(Input):
    current_password: str = Field(max_length=200)
    password: str = Field(min_length=16, max_length=200)


@app.post('/api/password')
def change_password(data: PasswordInput, request: Request, db: Db):
    user, current = authenticate(request, db, allow_change=True)
    if db.get(FeishuIdentity, user.id):
        raise HTTPException(403, '飞书账号的密码由飞书管理')
    try:
        verify_password(user.password_hash, data.current_password)
    except HTTPException:
        raise
    except Exception:
        raise SafeError('当前密码不正确') from None
    if data.current_password == data.password:
        raise SafeError('新密码不能与原密码相同')
    user.password_hash, user.must_change = hash_password(data.password), False
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id,
                                         LoginSession.token_hash != current.token_hash))
    audit(db, user.username, 'password_changed')
    db.commit()
    return {'ok': True}


def admin(request, db):
    return authenticate(request, db)[0]


def get_or_404(db, model, identity):
    item = db.get(model, identity)
    if not item:
        raise HTTPException(404, '记录不存在')
    if lifecycle.archived(db, model, identity):
        raise HTTPException(410, '记录已删除，请先在回收站恢复')
    return item


@app.get('/api/catalog')
def catalog(request: Request, db: Db):
    admin(request, db)
    return {'targets': TARGETS, 'issuer_v1': ISSUER_V1, 'issuer_v2': ISSUER_V2}


@app.get('/api/dashboard')
def dashboard(request: Request, db: Db):
    admin(request, db)
    versions = list(db.scalars(select(Version).join(Certificate, Certificate.latest_version_id == Version.id)
                              .where(Certificate.enabled == True)))
    targets = list(db.scalars(select(Target).where(Target.enabled == True, exclusions.managed())))
    worker = setting(db, 'worker')
    return {'certificates': db.scalar(select(func.count()).select_from(Certificate).where(Certificate.enabled == True)), 'targets': len(targets),
        'excluded_targets': db.scalar(select(func.count()).select_from(TargetExclusion)),
        'expiring': sum(0 <= (utc(v.not_after) - now()).total_seconds() <= 30 * 86400 for v in versions),
        'expired': sum(utc(v.not_after) <= now() for v in versions),
        'target_issues': sum(bool(t.checked_at) and (not t.observed.get('ok') or not t.observed.get('version_matches', True)) for t in targets),
        'pending_jobs': db.scalar(select(func.count()).select_from(Job).where(Job.state.in_(ACTIVE))),
        'failed_jobs': db.scalar(select(func.count()).select_from(Job).where(Job.state == 'failed')),
        'products': {key: sum(t.kind == key for t in targets) for key in TARGETS},
        'worker': worker, 'notifications': setting(db, 'notifications', {'enabled': False, 'days': [30, 15, 7, 3, 1]}),
        'alerts_failed': db.scalar(select(func.count()).select_from(Alert).where(Alert.state == 'failed')),
        'now': now()}


class CredentialInput(Input):
    name: str = Field(min_length=1, max_length=160)
    kind: Literal['aliyun', 'ssh', 'feishu', 'yunxiao']
    secrets: dict = Field(default_factory=dict)


def credential_public(row):
    return {'id': row.id, 'name': row.name, 'kind': row.kind, 'summary': row.summary, 'created_at': row.created_at}


def credential_summary(kind, data):
    if kind == 'aliyun':
        ak = data.get('access_key_id', '')
        return {'access_key_id': ak[:4] + '…' + ak[-4:] if len(ak) > 8 else '已保存', 'account_id': data.get('account_id', '')}
    if kind == 'ssh':
        return {k: data.get(k, '') for k in ('host', 'port', 'username', 'host_key', 'jump_credential_id')}
    if kind == 'yunxiao':
        return {'token': '已加密保存', 'organization_id': data.get('organization_id', ''),
                'test_pipeline_id': data.get('test_pipeline_id', '')}
    return {'webhook': '已加密保存', 'signed': bool(data.get('sign_secret'))}


@app.get('/api/credentials')
def credentials(request: Request, db: Db):
    admin(request, db)
    return [credential_public(row) for row in db.scalars(select(Credential).where(lifecycle.visible(Credential)).order_by(Credential.created_at))]


def save_credential(db, data, row=None):
    lifecycle.lock(db)
    if row:
        lifecycle.require(db, Credential, row.id)
    values = unseal(row.encrypted) if row else {}
    values.update({k: v for k, v in data.secrets.items() if v not in ('', None)})
    if len(json.dumps(values)) > 60000:
        raise SafeError('凭据内容超过大小限制')
    required = {'aliyun': ['access_key_id', 'access_key_secret'],
                'ssh': ['host', 'username', 'private_key', 'host_key'], 'feishu': ['webhook'],
                'yunxiao': ['token', 'organization_id']}[data.kind]
    if any(not values.get(k) for k in required):
        raise SafeError('请填写完整的必填凭据字段')
    if data.kind == 'ssh':
        if values.get('jump_credential_id'):
            jump = lifecycle.require(db, Credential, values['jump_credential_id'])
            if jump.kind != 'ssh':
                raise SafeError('跳板机需要 SSH 类型凭据')
        if not values['host_key'].startswith('SHA256:'):
            raise SafeError('请先获取并核对主机指纹')
        if not 1 <= int(values.get('port', 22)) <= 65535:
            raise SafeError('SSH 端口不正确')
    if data.kind == 'feishu' and not values['webhook'].startswith('https://open.feishu.cn/open-apis/bot/v2/hook/'):
        raise SafeError('飞书 Webhook 地址不正确')
    if data.kind == 'yunxiao':
        Yunxiao(values)
        if values.get('test_pipeline_id'):
            Yunxiao.identifier(values['test_pipeline_id'])
    if row:
        if row.kind != data.kind:
            raise SafeError('已有凭据不能修改类型，请新建凭据')
        row.name, row.encrypted = data.name, seal(values)
    else:
        row = Credential(name=data.name, kind=data.kind, encrypted=seal(values))
        db.add(row)
    row.summary = credential_summary(data.kind, values)
    db.flush()
    if values.get('jump_credential_id') == row.id:
        raise SafeError('跳板机不能引用自身')
    return row


@app.post('/api/credentials')
def create_credential(data: CredentialInput, request: Request, db: Db):
    user = admin(request, db)
    row = save_credential(db, data)
    audit(db, user.username, 'credential_created', row.id, kind=row.kind, name=row.name)
    db.commit()
    return credential_public(row)


@app.patch('/api/credentials/{identity}')
def update_credential(identity: str, data: CredentialInput, request: Request, db: Db):
    user = admin(request, db)
    row = save_credential(db, data, get_or_404(db, Credential, identity))
    audit(db, user.username, 'credential_updated', row.id, kind=row.kind)
    db.commit()
    return credential_public(row)


@app.post('/api/credentials/{identity}/test')
def test_credential(identity: str, request: Request, db: Db):
    user = admin(request, db)
    row = get_or_404(db, Credential, identity)
    secret = unseal(row.encrypted)
    if row.kind == 'aliyun':
        Aliyun(secret).rpc('cas', 'GetInstanceSummary')
        message = '证书管理 API 读取成功；各产品部署写权限将在执行任务时分别校验'
    elif row.kind == 'ssh':
        with connect(db, secret) as client:
            command(client, 'true')
        message = 'SSH 主机指纹和密钥认证通过'
    elif row.kind == 'yunxiao':
        if not secret.get('test_pipeline_id'):
            raise SafeError('请填写测试读取的流水线 ID')
        Yunxiao(secret).pipeline(secret['test_pipeline_id'])
        message = '云效流水线读取成功；测试不会触发流水线'
    else:
        send_feishu(secret, '证书控制台测试通知', '飞书通知连接测试成功。')
        message = '飞书返回成功'
    audit(db, user.username, 'credential_test', row.id, kind=row.kind)
    db.commit()
    return {'ok': True, 'message': message}


class FingerprintInput(Input):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)


@app.post('/api/ssh-fingerprint')
def ssh_fingerprint(data: FingerprintInput, request: Request, db: Db):
    admin(request, db)
    return {'fingerprint': get_fingerprint(data.host, data.port)}


def certificate_public(db, row):
    version = db.get(Version, row.latest_version_id) if row.latest_version_id else None
    result = {k: getattr(row, k) for k in ('id', 'name', 'domains', 'source', 'credential_id',
        'issuer_config', 'auto_renew', 'auto_deploy', 'renew_before_days', 'enabled', 'state', 'created_at')}
    result['latest_version'] = version_public(version)
    result['target_count'] = db.scalar(select(func.count()).select_from(Target).where(Target.certificate_id == row.id, Target.enabled == True, exclusions.managed()))
    return result


@app.get('/api/certificates')
def certificates(request: Request, db: Db):
    admin(request, db)
    return [certificate_public(db, c) for c in db.scalars(select(Certificate).where(lifecycle.visible(Certificate)).order_by(Certificate.created_at.desc()))]


class CertificateInput(Input):
    name: str = Field(min_length=1, max_length=160)
    domains: list[str] = Field(default_factory=list, max_length=100)
    source: Literal['upload', 'aliyun_v1', 'aliyun_v2'] = 'upload'
    credential_id: str | None = None
    issuer_config: dict = Field(default_factory=dict)
    auto_renew: bool = False
    auto_deploy: bool = False
    renew_before_days: int = Field(default=30, ge=1, le=120)
    enabled: bool = True


def check_certificate_config(db, data):
    lifecycle.lock(db)
    if data.credential_id:
        lifecycle.require(db, Credential, data.credential_id)
    if data.source == 'upload' and data.auto_renew:
        raise SafeError('上传来源不能自动签发，请选择阿里云申请来源')
    if data.source != 'upload':
        if not data.domains:
            raise SafeError('请填写申请域名')
        cred = db.get(Credential, data.credential_id) if data.credential_id else None
        if not cred or cred.kind != 'aliyun':
            raise SafeError('请选择阿里云凭据')
    for domain in data.domains:
        domain_name(domain)
    if data.issuer_config.get('dns_credential_id'):
        cred = lifecycle.require(db, Credential, data.issuer_config['dns_credential_id'])
        if not cred or cred.kind != 'aliyun':
            raise SafeError('DNS 凭据不存在')
    if len(json.dumps(data.issuer_config)) > 8000:
        raise SafeError('申请配置超过大小限制')


@app.post('/api/certificates')
def create_certificate(data: CertificateInput, request: Request, db: Db):
    user = admin(request, db)
    check_certificate_config(db, data)
    row = Certificate(**data.model_dump())
    row.domains = [domain_name(d) for d in row.domains]
    db.add(row)
    db.flush()
    audit(db, user.username, 'certificate_created', row.id)
    db.commit()
    return certificate_public(db, row)


@app.patch('/api/certificates/{identity}')
def update_certificate(identity: str, data: CertificateInput, request: Request, db: Db):
    user = admin(request, db)
    check_certificate_config(db, data)
    row = get_or_404(db, Certificate, identity)
    for key, value in data.model_dump().items():
        setattr(row, key, value)
    audit(db, user.username, 'certificate_updated', row.id)
    db.commit()
    return certificate_public(db, row)


class UploadInput(Input):
    cert_pem: str = Field(min_length=1, max_length=160000)
    key_pem: str = Field(default='', max_length=32000)
    impact_token: str | None = Field(default=None, min_length=1, max_length=12000)


@app.post('/api/certificates/{identity}/versions')
def upload_certificate(identity: str, data: UploadInput, request: Request, db: Db):
    user = admin(request, db)
    lifecycle.lock(db)
    row = get_or_404(db, Certificate, identity)
    if data.impact_token:
        relationships.confirm_preview(data.impact_token, relationships.update_preview(db, row))
    version = add_version(db, row, data.cert_pem, data.key_pem)
    audit(db, user.username, 'certificate_version_uploaded', row.id, fingerprint=version.fingerprint)
    auto_deploy(db, row, version)
    db.commit()
    return version_public(version)


@app.get('/api/certificates/{identity}/versions')
def versions(identity: str, request: Request, db: Db):
    admin(request, db)
    get_or_404(db, Certificate, identity)
    return [version_public(v) for v in db.scalars(select(Version).where(Version.certificate_id == identity)
                                                .order_by(Version.created_at.desc()))]


@app.post('/api/certificates/{identity}/issue')
def issue_certificate(identity: str, request: Request, db: Db):
    user = admin(request, db)
    row = get_or_404(db, Certificate, identity)
    if row.source == 'upload':
        raise SafeError('请先配置阿里云证书申请来源')
    job = enqueue(db, 'issue', certificate_id=row.id)
    audit(db, user.username, 'issue_requested', row.id, job_id=job.id)
    db.commit()
    return {'job_id': job.id}


class DeployConfirmation(Input):
    preview_token: str | None = Field(default=None, min_length=1, max_length=12000)


def certificate_plan(db, certificate):
    version = db.get(Version, certificate.latest_version_id) if certificate.latest_version_id else None
    targets = list(db.scalars(select(Target).where(Target.certificate_id == certificate.id)))
    return relationships.preview(db, certificate, targets, version, 'certificate_deploy', certificate.id)


def target_plan(db, target, action='deploy'):
    if action not in ('deploy', 'rollback'):
        raise SafeError('预览操作不支持')
    certificate = get_or_404(db, Certificate, target.certificate_id) if target.certificate_id else None
    identity = target.previous_version_id if action == 'rollback' else (certificate.latest_version_id if certificate else None)
    version = db.get(Version, identity) if identity else None
    if version and action == 'rollback':
        certificate = get_or_404(db, Certificate, version.certificate_id)
    if not certificate:
        raise SafeError('请先为此目标绑定证书')
    return relationships.preview(db, certificate, [target], version, 'target_' + action, target.id)


@app.get('/api/relationships')
def certificate_relationships(request: Request, db: Db):
    admin(request, db)
    return relationships.graph(db)


@app.get('/api/certificates/{identity}/deploy-preview')
def preview_certificate_deployment(identity: str, request: Request, db: Db):
    admin(request, db)
    plan = certificate_plan(db, get_or_404(db, Certificate, identity))
    return {k: v for k, v in plan.items() if not k.startswith('_')}


@app.get('/api/certificates/{identity}/update-preview')
def preview_certificate_update(identity: str, request: Request, db: Db):
    admin(request, db)
    plan = relationships.update_preview(db, get_or_404(db, Certificate, identity))
    return {k: v for k, v in plan.items() if not k.startswith('_')}


@app.get('/api/targets/{identity}/deploy-preview')
def preview_target_deployment(identity: str, request: Request, db: Db, action: str = 'deploy'):
    admin(request, db)
    plan = target_plan(db, get_or_404(db, Target, identity), action)
    return {k: v for k, v in plan.items() if not k.startswith('_')}


@app.post('/api/certificates/{identity}/deploy')
def deploy_certificate(identity: str, request: Request, db: Db, data: DeployConfirmation | None = None):
    user = admin(request, db)
    lifecycle.lock(db)
    row = get_or_404(db, Certificate, identity)
    plan = certificate_plan(db, row)
    if data and data.preview_token:
        relationships.confirm_preview(data.preview_token, plan)
    if not plan['can_submit']:
        raise SafeError('；'.join(plan['blockers']))
    jobs = [enqueue(db, 'deploy', row.id, t['id'], plan['version']['id']).id for t in plan['targets']]
    audit(db, user.username, 'deploy_all_requested', row.id, job_ids=jobs,
          version_id=plan['version']['id'], target_ids=[t['id'] for t in plan['targets']],
          preview_confirmed=bool(data and data.preview_token))
    db.commit()
    return {'job_ids': jobs}


class TargetInput(Input):
    name: str = Field(min_length=1, max_length=180)
    kind: str = Field(max_length=30)
    domain: str = Field(min_length=1, max_length=253)
    region: str = Field(default='cn-shenzhen', max_length=50)
    resource_key: str = Field(default='', max_length=500)
    credential_id: str | None = None
    certificate_id: str | None = None
    config: dict = Field(default_factory=dict)
    enabled: bool = True
    auto_deploy: bool = False


def save_target(db, data, row=None):
    lifecycle.lock(db)
    if row and db.get(TargetExclusion, row.id):
        raise SafeError('此目标已排除，请先在已排除列表恢复管理，再修改配置')
    if data.credential_id:
        lifecycle.require(db, Credential, data.credential_id)
    if data.kind not in TARGETS:
        raise SafeError('目标类型不支持')
    definition = TARGETS[data.kind]
    domain = domain_name(data.domain)
    if domain.startswith('*.'):
        raise SafeError('部署目标和探测需要具体域名，不能直接使用通配符')
    if not re.fullmatch(r'[a-z0-9-]+', data.region):
        raise SafeError('地域格式不正确')
    if definition['credential']:
        cred = lifecycle.require(db, Credential, data.credential_id) if data.credential_id else None
        if not cred or cred.kind != definition['credential']:
            raise SafeError('请选择该产品需要的凭据类型')
    if any(not data.config.get(key) for key in definition['required']):
        raise SafeError('请填写完整的产品部署配置')
    if data.kind in ('nginx', 'yunxiao'):
        check_path(data.config['certificate_path'])
        check_path(data.config['private_key_path'])
        if data.config['certificate_path'] == data.config['private_key_path']:
            raise SafeError('证书和私钥路径必须不同')
    if data.kind == 'yunxiao':
        Yunxiao.identifier(data.config['pipeline_id'])
        if data.config['certificate_path'].rsplit('/', 1)[0] != data.config['private_key_path'].rsplit('/', 1)[0]:
            raise SafeError('流水线证书和私钥需要位于同一目录，以便成对切换')
        if not data.certificate_id or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}', data.config['machine_id']):
            raise SafeError('云效部署需要绑定证书并填写主机唯一标识')
        try:
            interval = int(data.config.get('check_interval_hours', 24))
        except (TypeError, ValueError):
            raise SafeError('流水线巡检间隔应为小时数') from None
        if not 1 <= interval <= 168:
            raise SafeError('流水线巡检间隔范围为 1–168 小时')
    if data.config.get('certificate_role') == 'additional' and not data.config.get('accelerator_id'):
        raise SafeError('GA 扩展证书需要 AcceleratorId')
    if data.config.get('probe_port') and not 1 <= int(data.config['probe_port']) <= 65535:
        raise SafeError('探测端口不正确')
    if data.config.get('health_url') and not data.config['health_url'].startswith('https://'):
        raise SafeError('业务健康检查请使用 HTTPS 地址')
    required = data.config.get('required_domains', [])
    if not isinstance(required, list) or len(required) > 100 or any(not isinstance(d, str) for d in required):
        raise SafeError('云端证书范围格式不正确')
    for scope in required:
        domain_name(scope)
    if data.certificate_id:
        certificate = get_or_404(db, Certificate, data.certificate_id)
        version = db.get(Version, certificate.latest_version_id) if certificate.latest_version_id else None
        if version and not covers(version.domains, domain):
            raise SafeError('所选证书没有覆盖目标域名，请选择匹配的单域名或通配符证书')
        if version and any(not covers(version.domains, scope) for scope in required):
            raise SafeError('所选证书未覆盖此云资源的全部证书范围，替换会影响其他域名')
    if row and lifecycle.target_busy(db, row.id):
        changes = ('certificate_id', 'credential_id', 'domain', 'region', 'config', 'enabled')
        if any(getattr(row, key) != getattr(data, key) for key in changes):
            raise SafeError('此目标还有未结束的任务，请等待完成后再修改绑定或部署配置')
    if data.auto_deploy and (not data.certificate_id or data.kind == 'monitor'):
        raise SafeError('自动部署需要绑定证书和可部署的产品类型')
    values = data.model_dump()
    values['domain'] = domain
    values['resource_key'] = data.resource_key or f'{data.region}:{domain}:{json.dumps(data.config, sort_keys=True)}'[:500]
    if row:
        if row.observed.get('configuration_required'):
            row.observed = {}
            row.checked_at = None
        if row.certificate_id != data.certificate_id:
            latest = db.get(Version, certificate.latest_version_id) if data.certificate_id and certificate.latest_version_id else None
            row.observed = {**row.observed, 'expected_fingerprint': latest.fingerprint if latest else None,
                            'version_matches': not latest or row.observed.get('fingerprint') == latest.fingerprint}
        for key, value in values.items():
            setattr(row, key, value)
    else:
        row = Target(**values)
        db.add(row)
    db.flush()
    return row


def target_public(row, exclusion=None):
    result = {key: getattr(row, key) for key in ('id', 'name', 'kind', 'domain', 'region', 'resource_key',
        'credential_id', 'certificate_id', 'config', 'enabled', 'auto_deploy', 'deployed_version_id',
        'previous_version_id', 'observed', 'checked_at', 'created_at')}
    result.update(excluded=bool(exclusion), exclusion_reason=exclusion.reason if exclusion else '',
                  excluded_at=exclusion.created_at if exclusion else None,
                  excluded_by=exclusion.excluded_by if exclusion else '')
    if result['observed'].get('not_after'):
        result['observed'] = {**result['observed'], 'days_left': int((utc(datetime.fromisoformat(
            result['observed']['not_after'])) - now()).total_seconds() // 86400)}
    return result


@app.get('/api/targets')
def targets(request: Request, db: Db):
    admin(request, db)
    markers = {e.target_id: e for e in db.scalars(select(TargetExclusion))}
    return [target_public(t, markers.get(t.id)) for t in db.scalars(select(Target).order_by(Target.created_at.desc()))]


@app.get('/api/cloud-resources')
def cloud_resources(request: Request, db: Db):
    admin(request, db)
    from .cloud_discovery import RESOURCE_FIELDS, PRODUCTS
    rows, snapshots = [], []
    for credential in db.scalars(select(Credential).where(Credential.kind == 'aliyun', lifecycle.visible(Credential))):
        snapshot = setting(db, 'cloud_inventory:' + credential.id)
        if not snapshot:
            continue
        snapshots.append({'credential_id': credential.id, 'name': credential.name,
                          'synced_at': snapshot.get('synced_at')})
        rows.extend({**{k: r.get(k) for k in RESOURCE_FIELDS}, 'credential_id': credential.id,
                     'credential_name': credential.name}
                    for r in snapshot.get('resources', []) if r.get('CloudProduct') in PRODUCTS)
    return {'resources': rows, 'snapshots': snapshots}


@app.post('/api/targets')
def create_target(data: TargetInput, request: Request, db: Db):
    user = admin(request, db)
    row = save_target(db, data)
    audit(db, user.username, 'target_created', row.id, kind=row.kind)
    db.commit()
    return target_public(row)


@app.patch('/api/targets/{identity}')
def update_target(identity: str, data: TargetInput, request: Request, db: Db):
    user = admin(request, db)
    row = save_target(db, data, get_or_404(db, Target, identity))
    audit(db, user.username, 'target_updated', row.id)
    db.commit()
    return target_public(row)


class ExclusionInput(Input):
    reason: str = Field(default='手动排除', max_length=400)


@app.post('/api/targets/{identity}/exclude')
def exclude_target(identity: str, data: ExclusionInput, request: Request, db: Db):
    user = admin(request, db)
    lifecycle.lock(db)
    target = get_or_404(db, Target, identity)
    marker = exclusions.exclude(db, target, user.username, data.reason)
    db.commit()
    return target_public(target, marker)


@app.post('/api/targets/{identity}/include')
def include_target(identity: str, request: Request, db: Db):
    user = admin(request, db)
    lifecycle.lock(db)
    target = get_or_404(db, Target, identity)
    exclusions.include(db, target, user.username)
    db.commit()
    return target_public(target)


@app.post('/api/targets/{identity}/{action}')
def target_action(identity: str, action: str, request: Request, db: Db, data: DeployConfirmation | None = None):
    user = admin(request, db)
    lifecycle.lock(db)
    target = get_or_404(db, Target, identity)
    if db.get(TargetExclusion, identity):
        raise SafeError('此目标已排除，请先恢复管理并核对配置')
    if not target.enabled:
        raise SafeError('请先核对目标配置并启用，再执行检查或部署')
    if action == 'probe':
        job = enqueue(db, 'probe', target_id=identity)
    elif action in ('deploy', 'rollback'):
        if target.kind == 'monitor':
            raise SafeError('监控目标不能部署')
        if data and data.preview_token:
            relationships.confirm_preview(data.preview_token, target_plan(db, target, action))
        cert = get_or_404(db, Certificate, target.certificate_id) if target.certificate_id else None
        version_id = target.previous_version_id if action == 'rollback' else (cert.latest_version_id if cert else None)
        version = db.get(Version, version_id) if version_id else None
        validate_target_deploy(version, target)
        if action == 'rollback':
            if lifecycle.target_busy(db, target.id):
                raise SafeError('此目标还有未结束的任务，请等待完成后再回退')
            get_or_404(db, Certificate, version.certificate_id)
            target.certificate_id = version.certificate_id
        job = enqueue(db, 'deploy', target.certificate_id, target.id, version.id, args={'rollback': action == 'rollback'})
        if action == 'rollback':
            target.auto_deploy = False
    else:
        raise HTTPException(404, '操作不存在')
    audit(db, user.username, 'target_' + action, identity, job_id=job.id)
    db.commit()
    return {'job_id': job.id}


class DiscoverInput(Input):
    credential_id: str
    products: list[str] = Field(default_factory=lambda: ['dcdn', 'fc', 'clb', 'oss', 'waf', 'ga'])
    regions: list[str] = Field(default_factory=lambda: ['cn-shenzhen', 'cn-hangzhou'])


@app.post('/api/discover')
def discover_resources(data: DiscoverInput, request: Request, db: Db):
    user = admin(request, db)
    row = get_or_404(db, Credential, data.credential_id)
    if row.kind != 'aliyun':
        raise SafeError('请选择阿里云凭据')
    if not data.regions or any(not re.fullmatch(r'[a-z0-9-]+', r) for r in data.regions) or len(data.regions) > 30:
        raise SafeError('请填写合法地域，最多 30 个')
    job = enqueue(db, 'discover', args=data.model_dump())
    audit(db, user.username, 'discovery_requested', row.id, job_id=job.id)
    db.commit()
    return {'job_id': job.id}


@app.get('/api/cloud/{identity}/certificates')
def cloud_inventory(identity: str, request: Request, db: Db, page: int = 1):
    admin(request, db)
    row = get_or_404(db, Credential, identity)
    if row.kind != 'aliyun' or not 1 <= page <= 1000:
        raise SafeError('凭据类型或页码不正确')
    api = Aliyun(unseal(row.encrypted))
    # List APIs contain metadata only. Public/private PEM contents are fetched only by explicit import.
    def metadata_only(value):
        if isinstance(value, dict):
            return {k: metadata_only(v) for k, v in value.items() if
                    not any(word in k.lower() for word in ('private', 'secret', 'token')) and
                    k.lower() not in ('key', 'cert', 'csr')}
        if isinstance(value, list):
            return [metadata_only(v) for v in value]
        if isinstance(value, str) and '-----BEGIN ' in value:
            return '[PEM 内容已省略]'
        return value
    return metadata_only({'instances': api.cas_instances(page), 'certificates': api.cas_certificates(page)})


class ImportInput(Input):
    credential_id: str
    cert_id: int = Field(gt=0)
    name: str = Field(min_length=1, max_length=160)


@app.post('/api/cloud/import')
def import_cloud_certificate(data: ImportInput, request: Request, db: Db):
    user = admin(request, db)
    credential = get_or_404(db, Credential, data.credential_id)
    if credential.kind != 'aliyun':
        raise SafeError('请选择阿里云凭据')
    cert, key = Aliyun(unseal(credential.encrypted)).cas_download(data.cert_id)
    lifecycle.lock(db)
    lifecycle.require(db, Credential, credential.id)
    row, version, status = import_certificate_bundle(db, data.name, cert, key)
    audit(db, user.username, 'cloud_certificate_imported' if status == 'imported' else 'cloud_certificate_import_reused',
          row.id, cloud_cert_id=data.cert_id, credential_id=credential.id,
          version_id=version.id, import_status=status)
    db.commit()
    return {**certificate_public(db, row), 'import_status': status, 'imported_version_id': version.id,
            'imported_version_is_latest': row.latest_version_id == version.id}


@app.get('/api/jobs')
def jobs(request: Request, db: Db):
    admin(request, db)
    return [{k: getattr(j, k) for k in ('id', 'kind', 'certificate_id', 'target_id', 'version_id',
        'state', 'attempts', 'error', 'progress', 'created_at', 'updated_at', 'run_after')}
        for j in db.scalars(select(Job).order_by(Job.created_at.desc()).limit(200))]


@app.post('/api/jobs/{identity}/retry')
def retry_job(identity: str, request: Request, db: Db):
    user = admin(request, db)
    lifecycle.lock(db)
    job = get_or_404(db, Job, identity)
    lifecycle.check_job(db, job.certificate_id, job.target_id, job.version_id, job.args)
    if job.state not in ('failed', 'waiting'):
        raise SafeError('该任务当前不能重试')
    if job.state == 'failed':
        pipeline.reset_failed_execution(db, job)
    job.state, job.run_after, job.error = 'queued', now(), ''
    if job.kind == 'deploy' and job.progress.get('submitted'):
        job.progress = {**job.progress, 'verify_attempt': 0}
    if job.kind == 'issue':
        job.progress = {**job.progress, 'retry_started_at': now().isoformat()}
    audit(db, user.username, 'job_retry', job.id)
    db.commit()
    return {'job_id': job.id}


class NotificationInput(Input):
    enabled: bool = False
    credential_id: str | None = None
    days: list[int] = Field(default_factory=lambda: [30, 15, 7, 3, 1], max_length=20)


@app.get('/api/notifications')
def notifications(request: Request, db: Db):
    admin(request, db)
    return {'settings': setting(db, 'notifications', {'enabled': False, 'days': [30, 15, 7, 3, 1]}),
            'alerts': [{k: getattr(a, k) for k in ('id', 'title', 'content', 'state', 'attempts', 'error', 'created_at', 'sent_at')}
                       for a in db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(100))]}


@app.put('/api/notifications')
def save_notifications(data: NotificationInput, request: Request, db: Db):
    user = admin(request, db)
    lifecycle.lock(db)
    if any(not 0 <= d <= 365 for d in data.days):
        raise SafeError('提醒天数范围为 0–365')
    if data.enabled or data.credential_id:
        row = lifecycle.require(db, Credential, data.credential_id) if data.credential_id else None
        if not row or row.kind != 'feishu':
            raise SafeError('请先添加并选择飞书 Webhook 凭据')
    set_setting(db, 'notifications', data.model_dump())
    audit(db, user.username, 'notification_settings_updated')
    db.commit()
    return {'ok': True}


@app.get('/api/trash')
def trash(request: Request, db: Db):
    admin(request, db)
    return [{k: getattr(row, k) for k in ('kind', 'resource_id', 'name', 'deleted_by', 'deleted_at')}
            for row in db.scalars(select(ResourceArchive).order_by(ResourceArchive.deleted_at.desc()))]


def resource_kind(collection):
    kinds = {'certificates': 'certificate', 'credentials': 'credential'}
    if collection not in kinds:
        raise HTTPException(404, '不支持此资源类型')
    return kinds[collection]


@app.get('/api/{collection}/{identity}/deletion-check')
def deletion_check(collection: str, identity: str, request: Request, db: Db):
    admin(request, db)
    kind = resource_kind(collection)
    row = get_or_404(db, lifecycle.MODELS[kind], identity)
    refs = lifecycle.blockers(db, kind, identity)
    return {'id': row.id, 'name': row.name, 'can_delete': not refs, 'blockers': refs}


@app.delete('/api/{collection}/{identity}')
def delete_resource(collection: str, identity: str, request: Request, db: Db):
    user = admin(request, db)
    kind = resource_kind(collection)
    refs = lifecycle.archive(db, kind, identity, user.username)
    if refs:
        return JSONResponse({'detail': '仍被引用或存在未结束的任务，暂不能删除', 'blockers': refs}, status_code=409)
    audit(db, user.username, kind + '_deleted', identity, recoverable=True)
    db.commit()
    return {'ok': True, 'recoverable': True}


@app.post('/api/trash/{kind}/{identity}/restore')
def restore_resource(kind: str, identity: str, request: Request, db: Db):
    user = admin(request, db)
    if kind not in lifecycle.MODELS:
        raise HTTPException(404, '不支持此资源类型')
    row = lifecycle.restore(db, kind, identity)
    audit(db, user.username, kind + '_restored', identity)
    db.commit()
    return {'ok': True, 'id': row.id, 'name': row.name}


@app.get('/api/audit')
def audit_log(request: Request, db: Db):
    admin(request, db)
    return [{k: getattr(a, k) for k in ('id', 'actor', 'action', 'resource_id', 'details', 'created_at')}
        for a in db.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(200))]


static_dir = Path(__file__).parent / 'static'
if static_dir.is_dir():
    app.mount('/assets', StaticFiles(directory=static_dir / 'assets'), name='assets')


@app.get('/')
def index():
    path = static_dir / 'index.html'
    return FileResponse(path) if path.is_file() else JSONResponse({'status': 'frontend_not_built'}, status_code=503)


@app.get('/third-party-notices.txt')
def frontend_notices():
    path = static_dir / 'third-party-notices.txt'
    if not path.is_file():
        raise HTTPException(404, 'Frontend notices have not been built')
    return FileResponse(path, media_type='text/plain; charset=utf-8')
