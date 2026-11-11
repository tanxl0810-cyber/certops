import logging
import os
import time
from datetime import datetime, timedelta
import httpx
from sqlalchemy import and_, or_, select, text
from .db import (Certificate, Credential, Job, Session, Target, TargetExclusion, Version, init_db,
                 now, setting, set_setting, utc)
from .security import SafeError, audit, clean_error, unseal
from .certificates import add_version, covers, parse_bundle, probe, validate_target_deploy
from .cloud import Aliyun, discover
from .notifications import add_alert, deliver_pending, evaluate_expiry
from . import sshdeploy
from . import pipeline
from . import lifecycle
from . import exclusions

log = logging.getLogger('certops.worker')
ACTIVE = ('queued', 'running', 'waiting')


class Wait(Exception):
    def __init__(self, seconds, message=''):
        self.seconds, self.message = seconds, message


def enqueue(db, kind, certificate_id=None, target_id=None, version_id=None, args=None):
    lifecycle.lock(db)
    lifecycle.check_job(db, certificate_id, target_id, version_id, args)
    if db.bind.dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(64042026)'))
    candidates = select(Job).where(Job.kind == kind, Job.target_id == target_id,
        Job.certificate_id == certificate_id, Job.version_id == version_id, Job.state.in_(ACTIVE))
    existing = (next((j for j in db.scalars(candidates) if j.args == (args or {})), None)
                if kind == 'discover' else db.scalar(candidates))
    if existing:
        return existing
    job = Job(kind=kind, certificate_id=certificate_id, target_id=target_id,
              version_id=version_id, args=args or {}, progress={})
    db.add(job)
    db.flush()
    return job


def automatic_deploy_blocked(db, target_id, current_job_id=None):
    # A fresh automatic job must not bypass an older ambiguous cloud write.
    # A later, verified successful deployment establishes a new safe baseline.
    jobs = select(Job).where(Job.kind == 'deploy', Job.target_id == target_id)
    if current_job_id:
        jobs = jobs.where(Job.id != current_job_id)
    for previous in db.scalars(jobs.order_by(Job.created_at.desc(), Job.id.desc())):
        if previous.state == 'succeeded':
            return False
        if previous.progress.get('submission_started') and not previous.progress.get('submitted'):
            return True
    return False


def auto_deploy(db, certificate, version):
    if not certificate.enabled or not certificate.auto_deploy:
        return
    for target in db.scalars(select(Target).where(Target.certificate_id == certificate.id,
                                                Target.enabled == True, Target.auto_deploy == True, exclusions.managed())):
        if not automatic_deploy_blocked(db, target.id):
            enqueue(db, 'deploy', certificate.id, target.id, version.id, args={'automatic': True})


def credential_secret(db, credential_id, kind=None):
    if credential_id:
        lifecycle.require(db, Credential, credential_id)
    row = db.get(Credential, credential_id) if credential_id else None
    if not row or (kind and row.kind != kind):
        raise SafeError('缺少对应类型的访问凭据，请在控制台配置')
    return unseal(row.encrypted)


def progress(db, job, **changes):
    job.progress = {**job.progress, **changes}
    job.updated_at = now()
    db.commit()


def run_probe(db, target):
    if db.get(TargetExclusion, target.id):
        raise SafeError('此目标已排除，已停止巡检')
    previous = target.observed or {}
    try:
        observed = probe(target.domain, target.config.get('probe_address') or target.domain,
                         target.config.get('probe_port') or 443, ca_pem=target.config.get('ca_pem'))
        observed['observed_at'] = now().isoformat()
        if target.certificate_id:
            certificate = db.get(Certificate, target.certificate_id)
            latest = db.get(Version, certificate.latest_version_id) if certificate and certificate.latest_version_id else None
            observed['expected_fingerprint'] = latest.fingerprint if latest else None
            observed['version_matches'] = not latest or observed['fingerprint'] == latest.fingerprint
        target.observed = observed
        if previous.get('error') or previous.get('ok') is False:
            if observed.get('ok') and observed.get('version_matches', True):
                add_alert(db, f'recovery:{target.id}:{previous.get("error", previous.get("fingerprint"))}:{observed["fingerprint"]}',
                          '证书检查已恢复', f'域名：{target.domain}\n目标：{target.name}\n实际 TLS 检查已通过。')
    except Exception as exc:
        target.observed = {**previous, 'ok': False, 'error': clean_error(exc), 'probe_failed': True}
    target.checked_at = now()
    db.commit()
    return target.observed


def run_deploy(db, job):
    lifecycle.check_job(db, job.certificate_id, job.target_id, job.version_id, job.args)
    target, version = db.get(Target, job.target_id), db.get(Version, job.version_id)
    if not target or not target.enabled:
        raise SafeError('部署目标不存在或已停用')
    if target.certificate_id != version.certificate_id:
        raise SafeError('部署绑定已改变，当前任务已停止；请为新绑定创建任务')
    validate_target_deploy(version, target)
    if job.args.get('automatic') and automatic_deploy_blocked(db, target.id, job.id):
        raise SafeError('此目标有结果不明的云部署，自动部署已暂停；请先人工核对并重试原任务或创建新的手动部署任务。')
    if not job.progress.get('submitted'):
        if target.kind != 'nginx' and job.progress.get('submission_started'):
            # A crash or timeout may occur after the provider has accepted the write.
            # Reconcile the live certificate, but never blindly upload it again.
            observed = run_probe(db, target)
            if (observed.get('ok') and not observed.get('probe_failed')
                    and observed.get('fingerprint') == version.fingerprint):
                target.previous_version_id = job.progress.get('prior_deployed_version_id', target.deployed_version_id)
                progress(db, job, submitted=True, reconciled=True, verify_attempt=0)
            else:
                raise SafeError('上次云部署提交结果不明，已停止自动重发。请先检查云端资源及实际证书；'
                                '确认未生效后，通过新的部署预览创建任务。')
    if not job.progress.get('submitted'):
        secret = credential_secret(db, target.credential_id, 'ssh' if target.kind == 'nginx' else 'aliyun')
        if target.kind == 'nginx':
            result = sshdeploy.deploy(db, target, secret, version.cert_pem, unseal(version.key_encrypted), job.id)
        else:
            api = Aliyun(secret, target.region)
            progress(db, job, submission_started=True, prior_deployed_version_id=target.deployed_version_id)
            job_progress = {**job.progress, 'job_id': job.id}
            result = api.apply_target(target, version.cert_pem, unseal(version.key_encrypted),
                version.fingerprint, job_progress, lambda **changes: progress(db, job, **changes))
        target.previous_version_id = job.progress.get('prior_deployed_version_id', target.deployed_version_id)
        progress(db, job, submitted=True, submitted_at=now().isoformat(),
                 request_id=result.get('RequestId', ''), result={k: v for k, v in result.items()
                    if k in ('nginx_reload', 'backup_suffix', 'ListenerId')}, verify_attempt=0)
        db.commit()
    observed = run_probe(db, target)
    if not observed.get('probe_failed') and observed.get('fingerprint') == version.fingerprint and observed.get('ok'):
        if target.config.get('health_url'):
            try:
                with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
                    response = client.get(target.config['health_url'])
                if not 200 <= response.status_code < 300:
                    raise SafeError('业务健康检查返回错误状态')
            except Exception:
                raise SafeError('证书已更新，但业务健康检查未通过，请检查目标服务') from None
        target.deployed_version_id = version.id
        db.commit()
        return
    count = job.progress.get('verify_attempt', 0) + 1
    progress(db, job, verify_attempt=count)
    if count >= 8:
        raise SafeError('云 API 已提交或 Nginx 已重载，但实际 TLS 证书/信任链尚未验证通过；请检查探测地址、SNI、证书链及前置网关。未重复提交部署。')
    raise Wait(min(300, 15 * (2 ** min(count, 4))), '等待目标证书生效并通过 TLS 验证')


def dns_validate(db, certificate, job, records):
    config = certificate.issuer_config
    records = [r for r in records if r.get('name') and r.get('value')]
    progress(db, job, validation_records=records)
    if not config.get('auto_dns'):
        return
    done = job.progress.get('dns_records', [])
    api = Aliyun(credential_secret(db, config.get('dns_credential_id') or certificate.credential_id, 'aliyun'))
    for record in records:
        if record['type'] not in ('TXT', 'CNAME'):
            continue
        if any(item.get('fqdn') == record['name'] for item in done):
            continue
        result = api.put_dns_validation(record['name'], record['type'], record['value'])
        done = done + [result]
        progress(db, job, dns_records=done)


def finish_issue(db, certificate, job, cert_pem, key_pem):
    _, _, metadata = parse_bundle(cert_pem, key_pem)
    if any(not covers(metadata['domains'], d) for d in certificate.domains):
        raise SafeError('阿里云返回的证书未覆盖配置的申请域名，已停止保存和自动部署，请核对实例或订单 ID')
    version = add_version(db, certificate, cert_pem, key_pem)
    baseline = job.progress.get('baseline_fingerprint')
    if baseline and version.fingerprint == baseline:
        raise Wait(120, '云端尚未签发新版本')
    job.version_id = version.id
    if certificate.source == 'aliyun_v1' and certificate.issuer_config.get('order_id'):
        certificate.issuer_config = {**certificate.issuer_config, 'order_id': ''}
    progress(db, job, certificate_version_id=version.id, validation_records=[])
    auto_deploy(db, certificate, version)
    db.commit()


def run_issue(db, job):
    lifecycle.require(db, Certificate, job.certificate_id)
    certificate = db.get(Certificate, job.certificate_id)
    if not certificate or not certificate.enabled:
        raise SafeError('证书不存在或已停用')
    start = datetime.fromisoformat(job.progress['retry_started_at']) if job.progress.get('retry_started_at') else utc(job.created_at)
    if now() - start > timedelta(hours=48):
        raise SafeError('证书申请等待超过 48 小时，请在阿里云核对订单后重试')
    config = certificate.issuer_config
    api = Aliyun(credential_secret(db, certificate.credential_id, 'aliyun'))
    if 'baseline_fingerprint' not in job.progress:
        old = db.get(Version, certificate.latest_version_id) if certificate.latest_version_id else None
        progress(db, job, baseline_fingerprint=old.fingerprint if old else None)
    if certificate.source == 'aliyun_v2':
        instance = config.get('instance_id')
        if not instance:
            raise SafeError('请填写阿里云 V2.0 证书订阅实例 ID（cas_dv-cn-*）；系统不会自动购买订阅')
        current = api.rpc('cas', 'GetInstanceDetail', InstanceId=instance)
        cloud_id = current.get('CertificateId')
        # Existing issued certificates can be imported without consuming another application.
        if cloud_id and not job.progress.get('baseline_fingerprint') and not job.progress.get('apply_intent'):
            cert, key = api.cas_download(cloud_id)
            finish_issue(db, certificate, job, cert, key)
            return
        if not job.progress.get('apply_intent'):
            params = {'InstanceId': instance, 'Domain': ','.join(certificate.domains),
                      'ValidationMethod': 'DNS', 'GenerateCsrMethod': 'online',
                      'KeyAlgorithm': config.get('key_algorithm', 'RSA_2048')}
            if config.get('contact_ids'):
                params['ContactIdList'] = [int(x) for x in config['contact_ids']]
            api.rpc('cas', 'UpdateInstance', **params)
            progress(db, job, apply_intent=True, previous_cloud_id=cloud_id)
            result = api.rpc('cas', 'ApplyCertificate', InstanceId=instance)
            progress(db, job, task_id=result.get('TaskId'), request_id=result.get('RequestId'))
            raise Wait(15, '申请已提交，等待阿里云处理')
        if job.progress.get('task_id'):
            task = api.rpc('cas', 'GetTaskAttribute', TaskType='ApplyCertificate', TaskId=job.progress['task_id'])
            if task.get('TaskStatus') == 'failed':
                raise SafeError('阿里云申请失败：' + clean_error(task.get('TaskMessage', '请检查申请信息')))
        records = []
        for item in current.get('DomainValidationList', []):
            name = item.get('ValidationKey', '')
            domain = item.get('RootDomain') or item.get('Domain', '').removeprefix('*.')
            if name == '@':
                name = domain
            elif name and not name.rstrip('.').endswith(domain.rstrip('.')):
                name = name + '.' + domain
            records.append({'name': name, 'type': item.get('ValidationType', 'TXT'),
                            'value': item.get('ValidationValue', '')})
        dns_validate(db, certificate, job, records)
        if cloud_id and str(cloud_id) != str(job.progress.get('previous_cloud_id')):
            cert, key = api.cas_download(cloud_id)
            finish_issue(db, certificate, job, cert, key)
            return
        certificate.state = 'validating' if records else 'applying'
        db.commit()
        raise Wait(60, '等待域名验证或新证书签发')
    if certificate.source != 'aliyun_v1':
        raise SafeError('上传证书需要上传新版本；请先配置阿里云签发来源后再开启自动续签')
    order_id = job.progress.get('order_id') or config.get('order_id')
    if not order_id:
        if job.progress.get('apply_intent'):
            raise SafeError('申请请求结果不明，已停止重复申请以免再次消耗额度。请在阿里云确认订单，并在证书配置中填写订单 ID 后重试。')
        if not config.get('allow_resource_consumption'):
            raise SafeError('请在证书申请配置中确认使用已有证书资源包额度')
        params = {'ProductCode': config.get('product_code', 'digicert-free-1-free'),
                  'Domain': ','.join(certificate.domains), 'ValidateType': 'DNS',
                  'Username': config.get('contact_name'), 'Phone': config.get('phone'), 'Email': config.get('email')}
        if not all(params.get(k) for k in ('Username', 'Phone', 'Email')):
            raise SafeError('V1.0 申请需要联系人、手机号和邮箱')
        progress(db, job, apply_intent=True)
        result = api.rpc('cas', 'CreateCertificateForPackageRequest', **params)
        order_id = result.get('OrderId')
        if not order_id:
            raise SafeError('云端未返回订单 ID，请在阿里云确认申请结果后填写订单 ID；系统不会重复申请')
        progress(db, job, order_id=str(order_id), request_id=result.get('RequestId'))
    result = api.rpc('cas', 'DescribeCertificateState', OrderId=int(order_id))
    status = result.get('Type')
    if status == 'certificate':
        cert_pem, key_pem = result.get('Certificate'), result.get('PrivateKey')
        if not cert_pem:
            cert_pem, key_pem = api.cas_download(result['CertId'])
        finish_issue(db, certificate, job, cert_pem, key_pem)
        return
    if status == 'verify_fail':
        raise SafeError('阿里云证书审核失败，请检查联系人、域名验证和证书资源包')
    if status == 'domain_verify':
        name = result.get('RecordDomain', '')
        domain = certificate.domains[0].removeprefix('*.')
        # RecordDomain may be either a full hostname or a relative validation label.
        if name and not name.rstrip('.').endswith(domain):
            parts, labels = name.rstrip('.').split('.'), domain.split('.')
            overlap = 0
            for count in range(min(len(parts)-1, len(labels)), 0, -1):
                if parts[-count:] == labels[:count]:
                    overlap = count
                    break
            name = name.rstrip('.') + '.' + '.'.join(labels[overlap:])
        dns_validate(db, certificate, job, [{'name': name, 'type': result.get('RecordType', 'TXT'),
                                           'value': result.get('RecordValue', '')}])
    certificate.state = 'validating' if status == 'domain_verify' else 'applying'
    db.commit()
    raise Wait(60, '等待域名验证或 CA 审核')


def run_discover(db, job):
    args = job.args
    secret = credential_secret(db, args['credential_id'], 'aliyun')
    inventory = {}
    found, errors = discover(secret, args.get('products', ['dcdn', 'fc', 'clb', 'oss', 'waf', 'ga']),
                             args.get('regions', ['cn-shenzhen', 'cn-hangzhou']), inventory_snapshot=inventory)
    lifecycle.lock(db)
    lifecycle.require(db, Credential, args['credential_id'])
    added, excluded = 0, 0
    for item in found:
        existing = db.scalar(select(Target).where(Target.kind == item['kind'],
            Target.credential_id == args['credential_id'], Target.resource_key == item['resource_key']))
        if not existing:
            target = Target(**item, credential_id=args['credential_id'], auto_deploy=False)
            db.add(target); db.flush()
            if exclusions.provider_domain(target.kind, target.domain):
                exclusions.exclude(db, target, 'worker', exclusions.PROVIDER_REASON)
                excluded += 1
            else:
                added += 1
        elif db.get(TargetExclusion, existing.id):
            excluded += 1
    if 'resources' in inventory:
        set_setting(db, 'cloud_inventory:' + args['credential_id'],
                    {'resources': inventory['resources'], 'certificates': inventory.get('certificates', {}),
                     'synced_at': now().isoformat()})
    progress(db, job, found=len(found), added=added, excluded=excluded,
             cloud_associations=len(inventory.get('resources', [])), warnings=errors)
    if not found and errors:
        raise SafeError('资源发现未完成：' + '; '.join(errors)[:600])


def claim(db):
    # Expired leases are recoverable; submitted writes retain progress and only resume verification.
    for old in db.scalars(select(Job).where(Job.state == 'running', Job.lease_until < now())):
        old.state = 'waiting'
        old.run_after = now()
    job = db.scalar(select(Job).where(Job.state.in_(('queued', 'waiting')), Job.run_after <= now())
        .order_by(Job.run_after, Job.created_at).with_for_update(skip_locked=True).limit(1))
    if not job:
        db.commit()
        return None
    job.state, job.lease_until = 'running', now() + timedelta(minutes=10)
    job.attempts += 1
    job.updated_at = now()
    db.commit()
    return job


def process_one(db):
    job = claim(db)
    if not job:
        return False
    try:
        lifecycle.check_job(db, job.certificate_id, job.target_id, job.version_id, job.args)
        pipeline_target = db.get(Target, job.target_id) if job.target_id else None
        if job.kind in ('deploy', 'probe') and pipeline_target and pipeline_target.kind == 'yunxiao':
            pipeline.run_job(db, job, pipeline_target)
        elif job.kind == 'deploy':
            run_deploy(db, job)
        elif job.kind == 'issue':
            run_issue(db, job)
        elif job.kind == 'probe':
            target = db.get(Target, job.target_id)
            if not target or not target.enabled:
                raise SafeError('目标已停用')
            result = run_probe(db, target)
            if result.get('probe_failed'):
                raise SafeError(result['error'])
        elif job.kind == 'discover':
            run_discover(db, job)
        else:
            raise SafeError('未知任务类型')
        job.state, job.error = 'succeeded', ''
    except (Wait, pipeline.PipelineWait) as wait:
        job.state, job.error = 'waiting', wait.message
        job.run_after = now() + timedelta(seconds=wait.seconds)
    except Exception as exc:
        db.rollback()
        job = db.get(Job, job.id)
        job.state, job.error = 'failed', clean_error(exc)
        audit(db, 'worker', 'job_failed', job.id, kind=job.kind, reason=job.error)
        if setting(db, 'notifications').get('enabled'):
            add_alert(db, f'job-failed:{job.id}:{job.attempts}', '证书任务执行失败',
                      f'任务类型：{job.kind}\n任务 ID：{job.id}\n原因：{job.error}')
        log.warning('job=%s kind=%s failed=%s', job.id, job.kind, job.error)
    job.lease_until, job.updated_at = None, now()
    db.commit()
    return True


def schedule(db):
    heartbeat = setting(db, 'worker')
    set_setting(db, 'worker', {'heartbeat': now().isoformat(), 'version': os.getenv('APP_VERSION', '1.6.0')})
    for target in db.scalars(select(Target).where(Target.enabled == True, exclusions.managed())):
        interval = int(target.config.get('check_interval_hours', 24)) if target.kind == 'yunxiao' else 1
        if not target.checked_at or now() - utc(target.checked_at) > timedelta(hours=interval):
            enqueue(db, 'probe', target_id=target.id)
        cert = db.get(Certificate, target.certificate_id) if target.certificate_id else None
        if target.auto_deploy and cert and cert.enabled and cert.auto_deploy and cert.latest_version_id:
            version = db.get(Version, cert.latest_version_id)
            if version and version.key_encrypted and target.deployed_version_id != version.id:
                recent = db.scalar(select(Job).where(Job.target_id == target.id, Job.kind == 'deploy',
                    Job.version_id == version.id, Job.created_at > now() - timedelta(hours=24)).limit(1))
                if not recent and not automatic_deploy_blocked(db, target.id):
                    enqueue(db, 'deploy', cert.id, target.id, version.id, args={'automatic': True})
    for cert in db.scalars(select(Certificate).where(Certificate.enabled == True, Certificate.auto_renew == True)):
        version = db.get(Version, cert.latest_version_id) if cert.latest_version_id else None
        if not version or utc(version.not_after) - now() <= timedelta(days=cert.renew_before_days):
            recent = db.scalar(select(Job).where(Job.certificate_id == cert.id, Job.kind == 'issue',
                or_(Job.state.in_(ACTIVE), Job.created_at > now() - timedelta(hours=24))).limit(1))
            if not recent:
                enqueue(db, 'issue', certificate_id=cert.id)
    evaluate_expiry(db)
    db.commit()
    deliver_pending(db)


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    init_db()
    last_schedule = 0
    while True:
        try:
            with Session() as db:
                if time.monotonic() - last_schedule >= 45:
                    schedule(db)
                    last_schedule = time.monotonic()
                worked = process_one(db)
            if not worked:
                time.sleep(2)
        except Exception as exc:
            log.error('Worker loop: %s', clean_error(exc))
            time.sleep(5)


if __name__ == '__main__':
    main()
