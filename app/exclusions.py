"""Persistent resource exclusions retain cloud identity and deployment history."""
from sqlalchemy import select
from .db import Alert, Job, Target, TargetExclusion
from .security import SafeError, audit
from . import lifecycle

PROVIDER_REASON = '函数计算平台原生域名（*.fc.devsapp.net），不纳入业务证书管理'


def provider_domain(kind, domain):
    return kind == 'fc' and domain.lower().rstrip('.').endswith('.fc.devsapp.net')


def managed():
    return ~select(TargetExclusion.target_id).where(TargetExclusion.target_id == Target.id).exists()


def exclude(db, target, actor, reason='手动排除'):
    lifecycle.lock(db)
    if lifecycle.target_busy(db, target.id):
        raise SafeError('此目标还有未结束的任务，请等待任务结束后再排除')
    marker = db.get(TargetExclusion, target.id)
    if not marker:
        marker = TargetExclusion(target_id=target.id, reason=reason.strip() or '手动排除', excluded_by=actor)
        db.add(marker)
    target.enabled = target.auto_deploy = False
    # Pending messages for this target should not be delivered after exclusion.
    job_ids = set(db.scalars(select(Job.id).where(Job.target_id == target.id)))
    cancelled = 0
    for alert in db.scalars(select(Alert).where(Alert.state == 'pending')):
        parts = alert.dedupe_key.split(':')
        if (alert.dedupe_key.startswith(('expiry:target:' + target.id + ':', 'recovery:' + target.id + ':'))
                or len(parts) >= 2 and parts[0] == 'job-failed' and parts[1] in job_ids):
            alert.state = 'cancelled'
            cancelled += 1
    db.flush()
    audit(db, actor, 'target_excluded', target.id, reason=marker.reason, cancelled_alerts=cancelled)
    return marker


def include(db, target, actor):
    lifecycle.lock(db)
    marker = db.get(TargetExclusion, target.id)
    if not marker:
        return
    db.delete(marker)
    # Re-entry does not restart production automation without reviewing the config.
    target.enabled = target.auto_deploy = False
    db.flush()
    audit(db, actor, 'target_included', target.id)
