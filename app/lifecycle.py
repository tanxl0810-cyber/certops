"""Recoverable removal of unused console resources, preserving encrypted history."""
from sqlalchemy import select, text
from .db import (Certificate, Credential, Job, PipelineExecution, ResourceArchive,
                 Target, TargetExclusion, Version, now, setting)
from .security import SafeError

ACTIVE = ('queued', 'running', 'waiting')
MODELS = {'certificate': Certificate, 'credential': Credential}
KINDS = {model: kind for kind, model in MODELS.items()}
TERMINAL_RUNS = ('SUCCESS', 'FAIL', 'FAILED', 'CANCELED', 'CANCELLED', 'STOPPED')


def lock(db):
    # All reference edits and new/retried jobs take this transaction lock first.
    # Do not lock resource rows here: worker FK locks must not deadlock with enqueue.
    if db.get_bind().dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(64042027)'))


def visible(model):
    return ~select(ResourceArchive.resource_id).where(
        ResourceArchive.kind == KINDS[model], ResourceArchive.resource_id == model.id).exists()


def archived(db, model, identity):
    return model in KINDS and identity and db.get(ResourceArchive, (KINDS[model], identity)) is not None


def require(db, model, identity):
    row = db.get(model, identity) if identity else None
    if not row:
        raise SafeError('引用的记录不存在')
    if archived(db, model, identity):
        raise SafeError('引用的记录已删除，请先在回收站恢复')
    return row


def check_job(db, certificate_id=None, target_id=None, version_id=None, args=None):
    if certificate_id:
        certificate = require(db, Certificate, certificate_id)
        for identity in (certificate.credential_id, certificate.issuer_config.get('dns_credential_id')):
            if identity:
                require(db, Credential, identity)
    if version_id:
        version = require(db, Version, version_id)
        require(db, Certificate, version.certificate_id)
    if target_id:
        target = require(db, Target, target_id)
        if db.get(TargetExclusion, target_id):
            raise SafeError('此目标已排除，请先在已排除列表恢复管理并核对配置')
        if target.credential_id:
            require(db, Credential, target.credential_id)
        if target.certificate_id:
            require(db, Certificate, target.certificate_id)
    if (args or {}).get('credential_id'):
        require(db, Credential, args['credential_id'])


def pending_jobs(db):
    """Include ambiguous pipeline runs even after the local job has failed."""
    jobs = {j.id: j for j in db.scalars(select(Job).where(Job.state.in_(ACTIVE)))}
    for execution in db.scalars(select(PipelineExecution).where(PipelineExecution.expires_at > now())):
        if (execution.dispatch_at and execution.remote_status not in TERMINAL_RUNS
                and execution.state != 'rejected'):
            jobs.setdefault(execution.job_id, db.get(Job, execution.job_id))
    return [j for j in jobs.values() if j]


def target_busy(db, identity):
    return any(j.target_id == identity for j in pending_jobs(db))


def blockers(db, kind, identity):
    refs = []
    def add(category, row, message):
        refs.append({'kind': category, 'id': row.id, 'name': getattr(row, 'name', row.id), 'reason': message})

    jobs = pending_jobs(db)
    if kind == 'certificate':
        version_ids = set(db.scalars(select(Version.id).where(Version.certificate_id == identity)))
        for target in db.scalars(select(Target)):
            if target.certificate_id == identity:
                add('target', target, '部署目标仍绑定此证书（含停用目标）')
            elif target.deployed_version_id in version_ids or target.previous_version_id in version_ids:
                add('target', target, '部署目标仍保留此证书的已部署或回退版本')
        for job in jobs:
            if job.certificate_id == identity or job.version_id in version_ids:
                add('job', job, '关联任务尚未结束')
    elif kind == 'credential':
        for cert in db.scalars(select(Certificate).where(visible(Certificate))):
            if cert.credential_id == identity or cert.issuer_config.get('dns_credential_id') == identity:
                add('certificate', cert, '证书申请或 DNS 验证仍引用此凭据')
        for target in db.scalars(select(Target).where(Target.credential_id == identity)):
            add('target', target, '部署目标仍引用此凭据（含停用目标）')
        for credential in db.scalars(select(Credential).where(visible(Credential), Credential.kind == 'ssh')):
            if credential.summary.get('jump_credential_id') == identity:
                add('credential', credential, 'SSH 凭据仍将此记录作为跳板机')
        if setting(db, 'notifications').get('credential_id') == identity:
            refs.append({'kind': 'notifications', 'id': 'notifications', 'name': '飞书通知规则',
                         'reason': '请先在飞书通知中取消或更换机器人凭据'})
        for job in jobs:
            execution = db.get(PipelineExecution, job.id)
            if (job.args.get('credential_id') == identity or
                    execution and execution.snapshot.get('credential_id') == identity):
                add('job', job, '关联任务尚未结束')
    return refs


def archive(db, kind, identity, actor):
    lock(db)
    model = MODELS[kind]
    row = db.get(model, identity)
    if not row:
        raise SafeError('记录不存在')
    if archived(db, model, identity):
        return []
    refs = blockers(db, kind, identity)
    if refs:
        return refs
    if kind == 'certificate':
        row.enabled = row.auto_renew = row.auto_deploy = False
    db.add(ResourceArchive(kind=kind, resource_id=identity, name=row.name, deleted_by=actor))
    db.flush()
    return []


def restore(db, kind, identity):
    lock(db)
    item = db.get(ResourceArchive, (kind, identity))
    if not item:
        raise SafeError('回收站记录不存在')
    row = db.get(MODELS[kind], identity)
    dependencies = []
    if kind == 'certificate':
        dependencies = [row.credential_id, row.issuer_config.get('dns_credential_id')]
    elif row.kind == 'ssh':
        dependencies = [row.summary.get('jump_credential_id')]
    for identity in dependencies:
        if identity:
            require(db, Credential, identity)
    db.delete(item)
    db.flush()
    return row
