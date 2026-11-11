"""Pinned-version Yunxiao deployments and target-scoped machine authentication."""
import hashlib
import hmac
import json
import os
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from .certificates import covers, parse_bundle, validate_target_deploy, version_public
from .db import (Certificate, Credential, Job, PipelineExecution, PipelineRunner, Target, TargetExclusion, Version,
                 get_db, now, utc)
from .security import SafeError, audit, authenticate, token_hash, unseal
from .yunxiao import SubmissionUnknown, Yunxiao

router = APIRouter(prefix='/api')
Db = Annotated[object, Depends(get_db)]
ACTIVE = ('queued', 'running', 'waiting')
ERRORS = {'DOWNLOAD_FAILED', 'INVALID_BUNDLE', 'NGINX_TEST_FAILED', 'RELOAD_FAILED',
          'TLS_VERIFY_FAILED', 'HEALTH_FAILED', 'LOCAL_CONFIG_INVALID', 'INTERNAL_ERROR'}


@router.get('/pipeline/client.py')
def download_client():
    return FileResponse(Path(__file__).with_name('pipeline_client.py'), media_type='text/x-python', filename='certops-pipeline.py')


class PipelineWait(Exception):
    def __init__(self, seconds, message):
        self.seconds, self.message = seconds, message


class MachineInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    attempt_id: str = Field(min_length=36, max_length=36)
    machine_id: str = Field(min_length=1, max_length=100)
    pipeline_id: str = Field(pattern=r'^[1-9][0-9]{0,19}$')


class ReportInput(MachineInput):
    status: Literal['succeeded', 'failed']
    certificate_pem: str = Field(default='', max_length=160000)
    trusted: bool = False
    nginx_test_ok: bool = False
    nginx_reload_ok: bool = False
    health_ok: bool = False
    rolled_back: bool = False
    error_code: str = Field(default='', max_length=40)


def provision_runner(db, target):
    if db.get(TargetExclusion, target.id):
        raise SafeError('此目标已排除，请先恢复管理')
    if target.kind != 'yunxiao':
        raise SafeError('只有云效部署目标可以配置主机接入凭据')
    token = secrets.token_urlsafe(48)
    runner = db.get(PipelineRunner, target.id)
    if runner:
        runner.token_hash = token_hash(token)
        runner.created_at = now()
    else:
        db.add(PipelineRunner(target_id=target.id, token_hash=token_hash(token)))
    db.flush()
    return token


@router.post('/targets/{target_id}/pipeline-token')
def issue_runner_token(target_id: str, request: Request, db: Db):
    from . import lifecycle
    user, _ = authenticate(request, db)
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(404, '部署目标不存在')
    lifecycle.check_job(db, target_id=target_id)
    credential = db.get(Credential, target.credential_id)
    if not credential or credential.kind != 'yunxiao':
        raise SafeError('请先配置云效凭据')
    approved_hash = Yunxiao(unseal(credential.encrypted)).configuration_hash(target.config['pipeline_id'])
    lifecycle.lock(db)
    lifecycle.check_job(db, target_id=target_id)
    target.config = {**target.config, 'pipeline_config_sha256': approved_hash}
    token = provision_runner(db, target)
    audit(db, user.username, 'pipeline_runner_token_rotated', target.id)
    db.commit()
    return {'target_id': target.id, 'token': token, 'warning': '仅显示一次；旧凭据立即失效',
            'config': {'base_url': os.getenv('PUBLIC_URL', '').rstrip('/'), 'target_id': target.id,
                       'token': token, 'machine_id': target.config['machine_id'], 'pipeline_id': target.config['pipeline_id'],
                       'domain': target.domain, 'certificate_path': target.config['certificate_path'],
                       'private_key_path': target.config['private_key_path'], 'nginx_binary': '/usr/sbin/nginx',
                       'nginx_config': '/etc/nginx/nginx.conf', 'reload_argv': ['systemctl', 'reload', 'nginx'],
                       'probe_address': '127.0.0.1', 'probe_port': int(target.config.get('probe_port', 443))}}


def machine_execution(db, job_id, request, data, allow_completed=False):
    job = db.get(Job, job_id)
    execution = db.scalar(select(PipelineExecution).where(PipelineExecution.job_id == job_id).with_for_update())
    if not job or not execution:
        raise HTTPException(403, '部署任务或主机凭据无效')
    runner = db.get(PipelineRunner, execution.target_id)
    supplied = request.headers.get('authorization', '')
    token = supplied[7:] if supplied.startswith('Bearer ') else ''
    if not runner or not token or not hmac.compare_digest(runner.token_hash, token_hash(token)):
        raise HTTPException(403, '部署任务或主机凭据无效')
    target = db.get(Target, execution.target_id)
    snapshot = execution.snapshot
    if (not target or not target.enabled or target.kind != 'yunxiao' or
        target.certificate_id != job.certificate_id or target.credential_id != snapshot['credential_id'] or
        target.domain != snapshot['domain'] or data.attempt_id != execution.attempt_id or
        data.machine_id != snapshot['machine_id'] or data.pipeline_id != snapshot['pipeline_id'] or
        any(target.config.get(k) != snapshot.get(k) for k in ('pipeline_id', 'machine_id', 'certificate_path', 'private_key_path'))):
        raise HTTPException(409, '任务绑定已改变，请使用新的部署任务')
    if utc(execution.expires_at) <= now():
        raise HTTPException(410, '本次任务授权已过期')
    if not allow_completed and (job.state not in ACTIVE or execution.report_hash):
        raise HTTPException(409, '本次任务已结束，禁止继续下载或部署')
    version = db.get(Version, job.version_id)
    if not version or version.certificate_id != target.certificate_id:
        raise HTTPException(409, '任务指定的证书版本无效')
    return job, execution, target, version


@router.post('/pipeline/jobs/{job_id}/claim')
def claim_pipeline_job(job_id: str, data: MachineInput, request: Request, db: Db):
    job, execution, target, version = machine_execution(db, job_id, request, data, allow_completed=True)
    if execution.report_hash:
        return {'complete': True, 'status': execution.report.get('status')}
    if job.state not in ACTIVE or execution.state not in ('dispatching', 'running'):
        raise HTTPException(409, '任务尚未触发或已停止')
    execution.state = 'running'
    db.commit()
    return {'complete': False, 'job_id': job.id, 'target_id': target.id, 'attempt_id': execution.attempt_id,
            'operation': job.kind, 'version_id': version.id, 'fingerprint': version.fingerprint,
            'domain': target.domain, 'certificate_path': execution.snapshot['certificate_path'],
            'private_key_path': execution.snapshot['private_key_path'], 'expires_at': execution.expires_at}


@router.post('/pipeline/jobs/{job_id}/bundle')
def pipeline_bundle(job_id: str, data: MachineInput, request: Request, db: Db):
    job, execution, target, version = machine_execution(db, job_id, request, data)
    if execution.state != 'running' or job.kind != 'deploy':
        raise HTTPException(403, '本次任务没有证书下载权限')
    validate_target_deploy(version, target)
    audit(db, 'pipeline:' + data.machine_id, 'pipeline_bundle_downloaded', job.id, version_id=version.id)
    db.commit()
    return {'version_id': version.id, 'fingerprint': version.fingerprint,
            'cert_pem': version.cert_pem, 'key_pem': unseal(version.key_encrypted)}


@router.post('/pipeline/jobs/{job_id}/report')
def pipeline_report(job_id: str, data: ReportInput, request: Request, db: Db):
    job, execution, target, version = machine_execution(db, job_id, request, data, allow_completed=True)
    digest = hashlib.sha256(json.dumps(data.model_dump(), sort_keys=True).encode()).hexdigest()
    if execution.report_hash:
        if execution.report_hash != digest:
            raise HTTPException(409, '已接收的验证结果不可更改')
        return {'ok': True, 'duplicate': True}
    if job.state not in ACTIVE or execution.state != 'running':
        raise HTTPException(409, '本次任务已停止或尚未领取')
    if data.error_code and data.error_code not in ERRORS:
        raise SafeError('未知的主机执行错误码')
    observed = {}
    if data.certificate_pem:
        if 'PRIVATE KEY' in data.certificate_pem:
            raise SafeError('验证回传禁止包含私钥')
        _, _, observed = parse_bundle(data.certificate_pem)
        observed['valid_now'] = utc(observed['not_before']) <= now() < utc(observed['not_after'])
        observed['not_before'] = observed['not_before'].isoformat()
        observed['not_after'] = observed['not_after'].isoformat()
    if data.status == 'succeeded':
        if (not observed or not observed.get('valid_now') or not data.trusted or not data.health_ok or
            not covers(observed['domains'], target.domain) or
            (job.kind == 'deploy' and (observed['fingerprint'] != version.fingerprint or
                                      not data.nginx_test_ok or not data.nginx_reload_ok))):
            raise SafeError('主机回传未通过证书、域名、检查或重载验证')
    observed.update(source='pipeline_local', machine_id=data.machine_id, trusted=data.trusted,
                    hostname_valid=bool(observed) and covers(observed.get('domains', []), target.domain),
                    ok=data.status == 'succeeded', observed_at=now().isoformat())
    execution.report = {'status': data.status, 'observed': observed, 'error_code': data.error_code,
                        'rolled_back': data.rolled_back, 'nginx_test_ok': data.nginx_test_ok,
                        'nginx_reload_ok': data.nginx_reload_ok, 'health_ok': data.health_ok}
    execution.report_hash = digest
    execution.state = 'verified' if data.status == 'succeeded' else 'failed'
    audit(db, 'pipeline:' + data.machine_id, 'pipeline_result_received', job.id,
          status=data.status, fingerprint=observed.get('fingerprint'), rolled_back=data.rolled_back)
    db.commit()
    return {'ok': True}


def prepare_execution(db, job, target):
    db.scalar(select(Target).where(Target.id == target.id).with_for_update())
    other = db.scalar(select(PipelineExecution).join(Job, Job.id == PipelineExecution.job_id)
        .where(PipelineExecution.target_id == target.id, PipelineExecution.job_id != job.id,
               Job.state.in_(ACTIVE), PipelineExecution.expires_at > now()).limit(1))
    if other:
        db.commit()
        raise PipelineWait(30, '同一主机目标的前一任务尚未结束')
    if job.kind == 'probe':
        certificate = db.get(Certificate, target.certificate_id)
        if not certificate or not certificate.latest_version_id:
            raise SafeError('流水线检查需要绑定已有证书版本')
        job.certificate_id, job.version_id = certificate.id, certificate.latest_version_id
    if target.certificate_id != job.certificate_id:
        raise SafeError('部署绑定已改变，请创建新任务')
    version = db.get(Version, job.version_id)
    if not version:
        raise SafeError('证书版本不存在')
    if job.kind == 'deploy':
        validate_target_deploy(version, target)
    if not db.get(PipelineRunner, target.id):
        raise SafeError('尚未配置目标主机的流水线接入凭据')
    snapshot = {**target.config, 'domain': target.domain, 'credential_id': target.credential_id}
    execution = PipelineExecution(job_id=job.id, target_id=target.id, snapshot=snapshot,
                                  expires_at=now() + timedelta(hours=1))
    db.add(execution)
    db.commit()
    return execution


def run_job(db, job, target):
    from . import lifecycle
    lifecycle.check_job(db, job.certificate_id, job.target_id, job.version_id, job.args)
    execution = db.get(PipelineExecution, job.id) or prepare_execution(db, job, target)
    if not target.enabled or target.certificate_id != job.certificate_id:
        raise SafeError('目标已停用或证书绑定已改变')
    if utc(execution.expires_at) <= now():
        raise SafeError('等待云效执行或主机回传超过一小时，请核对流水线')
    credential = db.get(Credential, execution.snapshot['credential_id'])
    if not credential or credential.kind != 'yunxiao':
        raise SafeError('请配置云效访问凭据')
    api = Yunxiao(unseal(credential.encrypted))
    pipeline_id = execution.snapshot['pipeline_id']
    if not execution.dispatch_at:
        expected_hash = execution.snapshot.get('pipeline_config_sha256')
        if expected_hash and api.configuration_hash(pipeline_id) != expected_hash:
            raise SafeError('云效流程配置已变化，请核对脚本后重新配置主机接入')
        execution.dispatch_at, execution.state = now(), 'dispatching'
        db.commit()
        variables = {'CERTOPS_JOB_ID': job.id, 'CERTOPS_ATTEMPT_ID': execution.attempt_id}
        try:
            run_id = api.start(pipeline_id, variables)
        except SubmissionUnknown:
            raise PipelineWait(30, '触发结果等待确认，正在按任务标识查找运行实例') from None
        except SafeError:
            execution.state = 'rejected'
            db.commit()
            raise
        # The machine may already have claimed/reported while the OpenAPI call was in flight.
        db.refresh(execution)
        execution.pipeline_run_id = run_id
        job.progress = {**job.progress, 'submitted': True, 'pipeline_id': pipeline_id,
                        'pipeline_run_id': run_id, 'verification_source': 'pipeline_local'}
        db.commit()
    if not execution.pipeline_run_id:
        execution.pipeline_run_id = api.find_run(pipeline_id, job.id, execution.attempt_id, utc(execution.dispatch_at)) or ''
        db.commit()
        if not execution.pipeline_run_id:
            if now() - utc(execution.dispatch_at) > timedelta(minutes=5):
                raise SafeError('触发结果未确认，已停止自动重复触发，请在云效核对本次任务')
            raise PipelineWait(30, '等待云效运行实例确认')
    detail = api.run(pipeline_id, execution.pipeline_run_id)
    status = str(detail.get('status', '')).upper()
    db.refresh(execution)
    execution.remote_status = status
    db.commit()
    if status in ('FAIL', 'FAILED', 'CANCELED', 'CANCELLED', 'STOPPED'):
        raise SafeError('云效流水线失败或已停止；主机回传：' + execution.report.get('error_code', '尚未收到'))
    if status != 'SUCCESS':
        raise PipelineWait(20, '等待云效流水线执行完成')
    if not execution.report_hash:
        if not execution.finished_seen_at:
            execution.finished_seen_at = now()
            db.commit()
        if now() - utc(execution.finished_seen_at) > timedelta(minutes=2):
            raise SafeError('流水线已结束但缺少目标主机验证回传，不能标记部署成功')
        raise PipelineWait(15, '流水线已结束，等待主机验证回传')
    if execution.report.get('status') != 'succeeded':
        raise SafeError('主机更新未通过：' + execution.report.get('error_code', 'INTERNAL_ERROR'))
    version = db.get(Version, job.version_id)
    certificate = db.get(Certificate, target.certificate_id)
    latest = db.get(Version, certificate.latest_version_id) if certificate else None
    observed = execution.report['observed']
    target.observed = {**observed, 'expected_fingerprint': latest.fingerprint if latest else None,
                       'version_matches': not latest or observed.get('fingerprint') == latest.fingerprint,
                       'pipeline_run_id': execution.pipeline_run_id}
    target.checked_at = now()
    if job.kind == 'deploy' and target.deployed_version_id != version.id:
        target.previous_version_id = target.deployed_version_id
        target.deployed_version_id = version.id
    job.progress = {**job.progress, 'submitted': True, 'pipeline_id': pipeline_id,
                    'pipeline_run_id': execution.pipeline_run_id, 'verification_source': 'pipeline_local',
                    'fingerprint': observed.get('fingerprint'), 'nginx_reload': execution.report.get('nginx_reload_ok')}
    db.commit()


def reset_failed_execution(db, job):
    execution = db.get(PipelineExecution, job.id)
    if not execution:
        return
    if (execution.dispatch_at and execution.remote_status not in ('FAIL', 'FAILED', 'CANCELED', 'CANCELLED', 'STOPPED', 'SUCCESS')
        and execution.state != 'rejected'):
        raise SafeError('前一次云效运行状态尚未确认，禁止重复触发；请核对运行实例')
    db.delete(execution)
    db.flush()
    job.progress = {}
