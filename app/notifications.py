import base64
import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import httpx
from sqlalchemy import select
from .db import Alert, Credential, Target, Certificate, Version, now, utc, setting
from .security import SafeError, unseal, clean_error


def feishu_payload(title, content, secret='', public_url=None):
    payload = {'msg_type': 'interactive', 'card': {
        'schema': '2.0', 'config': {'update_multi': True},
        'header': {'title': {'tag': 'plain_text', 'content': title}, 'template': 'blue'},
        'body': {'elements': [
            {'tag': 'markdown', 'content': content.replace('<', '&lt;').replace('>', '&gt;')},
            {'tag': 'markdown', 'content': f'[打开证书控制台]({public_url or os.getenv("PUBLIC_URL", "")})'}]}}}
    if secret:
        timestamp = str(int(time.time()))
        payload.update(timestamp=timestamp, sign=base64.b64encode(
            hmac.new((timestamp + '\n' + secret).encode(), b'', hashlib.sha256).digest()).decode())
    return payload


def send_feishu(secret, title, content, transport=None):
    webhook = secret.get('webhook', '')
    if not webhook.startswith('https://open.feishu.cn/open-apis/bot/v2/hook/'):
        raise SafeError('飞书 Webhook 地址不正确')
    try:
        with httpx.Client(timeout=12, transport=transport, follow_redirects=False, trust_env=False) as client:
            response = client.post(webhook, json=feishu_payload(title, content, secret.get('sign_secret', '')))
            response.raise_for_status()
            data = response.json()
            if data.get('code', data.get('StatusCode', -1)) != 0:
                raise SafeError('飞书拒绝通知，错误码 ' + str(data.get('code', data.get('StatusCode'))))
    except SafeError:
        raise
    except Exception:
        raise SafeError('飞书通知发送失败或超时，将按策略重试') from None


def add_alert(db, key, title, content):
    if len(key) > 400:
        key = 'sha256:' + hashlib.sha256(key.encode()).hexdigest()
    if db.scalar(select(Alert).where(Alert.dedupe_key == key)):
        return
    db.add(Alert(dedupe_key=key, title=title, content=content))


def evaluate_expiry(db):
    from . import exclusions
    config = setting(db, 'notifications', {'enabled': False})
    if not config.get('enabled'):
        return
    thresholds = sorted(set(config.get('days', [30, 15, 7, 3, 1])), reverse=True)
    date = now().astimezone(ZoneInfo('Asia/Shanghai')).date().isoformat()
    for target in db.scalars(select(Target).where(Target.enabled == True, exclusions.managed())):
        observed = target.observed or {}
        days = observed.get('days_left')
        if observed.get('not_after'):
            days = int((utc(datetime.fromisoformat(observed['not_after'])) - now()).total_seconds() // 86400)
        if days is None:
            continue
        band = min((n for n in thresholds if days <= n), default=None)
        if days < 0:
            band = -1
        if band is None:
            continue
        key = f'expiry:target:{target.id}:{observed.get("fingerprint", "unknown")}:{band}:{date}'
        add_alert(db, key, '证书已过期' if days < 0 else '证书临近到期',
            f'域名：{target.domain}\n目标：{target.name}（{target.kind}）\n'
            f'实际证书到期：{observed.get("not_after", "未知")}\n剩余天数：{days}\n'
            f'状态：{"正常" if observed.get("ok") else "需要检查"}')
    for cert in db.scalars(select(Certificate).where(Certificate.enabled == True)):
        version = db.get(Version, cert.latest_version_id) if cert.latest_version_id else None
        if not version:
            continue
        days = int((utc(version.not_after) - now()).total_seconds() // 86400)
        band = min((n for n in thresholds if days <= n), default=None)
        if days < 0:
            band = -1
        if band is not None:
            add_alert(db, f'expiry:library:{cert.id}:{version.fingerprint}:{band}:{date}',
                '证书库到期提醒', f'证书：{cert.name}\n域名：{", ".join(version.domains)}\n'
                f'证书库版本剩余：{days} 天\n自动续签：{"开启" if cert.auto_renew else "关闭"}')


def deliver_pending(db):
    from . import lifecycle
    config = setting(db, 'notifications', {'enabled': False})
    if not config.get('enabled') or not config.get('credential_id'):
        return
    credential = db.get(Credential, config['credential_id'])
    if not credential or credential.kind != 'feishu' or lifecycle.archived(db, Credential, credential.id):
        return
    for alert in db.scalars(select(Alert).where(Alert.state == 'pending', Alert.next_attempt <= now())
                             .order_by(Alert.created_at).limit(4)):
        try:
            send_feishu(unseal(credential.encrypted), alert.title, alert.content)
            alert.state, alert.sent_at, alert.error = 'sent', now(), ''
        except SafeError as exc:
            alert.attempts += 1
            alert.error = clean_error(exc)
            alert.next_attempt = now() + timedelta(minutes=min(60, 2 ** min(alert.attempts, 6)))
            if alert.attempts >= 12:
                alert.state = 'failed'
        db.commit()
