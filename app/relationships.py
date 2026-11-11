"""Certificate-to-service relationships, with separate evidence and deployment intent."""
import hashlib
import json
from datetime import timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select
from .db import Certificate, Credential, Target, TargetExclusion, Version, now, setting
from .catalog import TARGETS
from .certificates import covers, validate_target_deploy, version_public
from .security import SafeError, clean_error, seal, unseal
from . import lifecycle


def fingerprint(value):
    value = str(value or '').replace(':', '').lower().strip()
    return value if len(value) in (40, 64) and all(c in '0123456789abcdef' for c in value) else ''


def cloud_target(row, targets):
    for target in targets:
        if target.credential_id != row['credential_id']:
            continue
        product, config = row.get('CloudProduct'), target.config
        if product == 'DCDN' and target.kind == 'dcdn' and target.domain == row.get('Domain'):
            return target
        if product == 'FC' and target.kind == 'fc' and target.domain == row.get('Domain'):
            if not row.get('RegionId') or row['RegionId'] == target.region:
                return target
        if product == 'OSS' and target.kind == 'oss' and config.get('bucket') == row.get('InstanceId') and target.domain == row.get('Domain'):
            return target
        if (product == 'GA' and target.kind == 'ga' and config.get('listener_id') == row.get('ListenerId')
                and (config.get('cloud_domain') or target.domain) == row.get('Domain')):
            return target
        if product == 'SLB' and target.kind == 'clb' and config.get('load_balancer_id') == row.get('InstanceId'):
            if str(config.get('listener_port', 443)) == str(row.get('ListenerPort')) and config.get('cloud_domain') == row.get('Domain'):
                return target
        if product == 'WAF' and target.kind == 'waf_cloud' and config.get('resource_instance_id') == row.get('InstanceId') and config.get('cloud_domain') == row.get('Domain'):
            return target
    return None


def destination(target, credentials):
    config = target.config
    credential = credentials.get(target.credential_id)
    summary = credential.summary if credential else {}
    kind = target.kind
    resource = {'dcdn': target.domain, 'fc': target.domain, 'oss': config.get('bucket'),
        'ga': config.get('accelerator_id') or config.get('listener_id'),
        'clb': config.get('load_balancer_id'), 'waf': config.get('instance_id'),
        'waf_cloud': config.get('resource_instance_id'), 'monitor': target.domain}.get(kind)
    machine = config.get('machine_id') if kind == 'yunxiao' else summary.get('host') if kind == 'nginx' else ''
    operation = ('更新证书文件、检查配置并重载 Nginx' if kind in ('nginx', 'yunxiao') else
                 '更新 WAF 接入入口的证书' if kind == 'waf_cloud' else
                 '仅检查 HTTPS，不部署证书' if kind == 'monitor' else '更新云产品证书配置')
    return {'product': TARGETS.get(kind, {}).get('label', kind), 'resource_id': resource or machine or target.domain,
        'machine': machine or (config.get('resource_instance_id') if kind == 'waf_cloud' else ''),
        'address': summary.get('host') if kind == 'nginx' else config.get('probe_address', ''),
        'port': config.get('listener_port') or config.get('port') or config.get('probe_port') or 443,
        'listener_id': config.get('listener_id') or config.get('cloud_resource_id') or config.get('domain_extension_id') or '',
        'pipeline_id': config.get('pipeline_id', ''), 'certificate_path': config.get('certificate_path', ''),
        'private_key_path': config.get('private_key_path', ''), 'operation': operation,
        'cloud_scope': config.get('cloud_domain') or target.domain,
        'required_domains': config.get('required_domains') or [target.domain], 'region': target.region}


def deployment_reason(db, certificate, target, version, excluded):
    if excluded:
        return '目标已排除'
    if not target.enabled:
        return '待配置探测域名' if target.observed.get('configuration_required') else '目标已停用'
    if target.kind == 'monitor':
        return '仅监控，不部署证书'
    try:
        lifecycle.check_job(db, certificate.id, target.id, version.id if version else None)
        validate_target_deploy(version, target)
    except SafeError as exc:
        if version and str(exc) == '证书没有覆盖目标域名':
            missing = [d for d in [target.domain, *target.config.get('required_domains', [])] if not covers(version.domains, d)]
            return '当前版本未覆盖：' + '、'.join(dict.fromkeys(missing))
        return clean_error(exc)
    return ''


def graph(db):
    all_certificates = {c.id: c for c in db.scalars(select(Certificate))}
    certificates = [c for c in all_certificates.values() if not lifecycle.archived(db, Certificate, c.id)]
    credentials = {c.id: c for c in db.scalars(select(Credential))}
    targets = list(db.scalars(select(Target).order_by(Target.kind, Target.name, Target.id)))
    exclusions = {e.target_id for e in db.scalars(select(TargetExclusion))}
    versions, version_hashes = {}, {}
    for version in db.scalars(select(Version)):
        versions[version.id] = version
        try:
            sha1 = x509.load_pem_x509_certificate(version.cert_pem.encode()).fingerprint(hashes.SHA1()).hex()
        except ValueError:
            sha1 = ''
        version_hashes[version.id] = {version.fingerprint, sha1} - {''}
    source_rows, snapshots, pending = [], [], []
    for credential in credentials.values():
        if credential.kind != 'aliyun' or lifecycle.archived(db, Credential, credential.id):
            continue
        snapshot = setting(db, 'cloud_inventory:' + credential.id)
        if not snapshot:
            continue
        snapshots.append({'credential_id': credential.id, 'name': credential.name, 'synced_at': snapshot.get('synced_at')})
        if snapshot.get('resources') and not snapshot.get('certificates'):
            pending.append(credential.name)
        metadata = snapshot.get('certificates', {})
        for row in snapshot.get('resources', []):
            row = {**row, 'credential_id': credential.id, 'synced_at': snapshot.get('synced_at')}
            row['fingerprint'] = fingerprint(metadata.get(str(row.get('CertId')), {}).get('fingerprint'))
            source_rows.append(row)
    target_status = {}
    for target in targets:
        actual = next((v for v in versions.values() if target.checked_at and v.fingerprint == fingerprint(target.observed.get('fingerprint'))), None)
        actual_certificate = all_certificates.get(actual.certificate_id) if actual else None
        bound = all_certificates.get(target.certificate_id)
        latest = versions.get(bound.latest_version_id) if bound else None
        target_status[target.id] = {'actual_certificate_id': actual_certificate.id if actual_certificate else None,
            'actual_certificate_name': actual_certificate.name if actual_certificate else None,
            'matches_bound_latest': bool(latest and target.checked_at and latest.fingerprint == target.observed.get('fingerprint')),
            'checked_at': target.checked_at}
    result = []
    for certificate in certificates:
        own = {v.id: v for v in versions.values() if v.certificate_id == certificate.id}
        by_hash = {h: v for v in own.values() for h in version_hashes[v.id]}
        latest = versions.get(certificate.latest_version_id)
        rows, cloud_count = {}, 0
        def target_row(target):
            if target.id not in rows:
                bound = all_certificates.get(target.certificate_id)
                is_bound = target.certificate_id == certificate.id
                reason = deployment_reason(db, certificate, target, latest, target.id in exclusions) if is_bound else ''
                manual = is_bound and target.enabled and target.id not in exclusions and target.kind != 'monitor'
                automatic = bool(is_bound and target.enabled and target.id not in exclusions and target.kind != 'monitor'
                                 and certificate.enabled and certificate.auto_deploy and target.auto_deploy)
                rows[target.id] = {'id': target.id, 'target_id': target.id, 'name': target.name,
                    'kind': target.kind, 'domain': target.domain, 'destination': destination(target, credentials),
                    'binding': 'bound' if is_bound else 'other' if bound else 'unbound',
                    'bound_certificate_id': bound.id if bound else None, 'bound_certificate_name': bound.name if bound else None,
                    'enabled': target.enabled, 'excluded': target.id in exclusions,
                    'configuration_required': bool(target.observed.get('configuration_required')),
                    'manual_included': bool(manual), 'manual_ready': bool(manual and not reason),
                    'manual_reason': reason, 'automatic_on_new_version': automatic,
                    'evidence': [], 'cloud': [], 'tls': None, 'status': target_status[target.id]}
            return rows[target.id]
        for target in targets:
            if target.certificate_id == certificate.id:
                target_row(target)['evidence'].append('binding')
            matched = by_hash.get(fingerprint(target.observed.get('fingerprint'))) if target.checked_at else None
            if matched:
                row = target_row(target)
                row['evidence'].append('tls')
                row['tls'] = {'checked_at': target.checked_at, 'version_id': matched.id,
                              'is_latest': matched.id == certificate.latest_version_id, 'ok': target.observed.get('ok')}
        for source in source_rows:
            matched = by_hash.get(source['fingerprint'])
            if not matched:
                continue  # Names and overlapping domains are not proof of certificate identity.
            cloud_count += 1
            target = cloud_target(source, targets)
            if target:
                row = target_row(target)
            else:
                identity = 'cloud:' + source['credential_id'] + ':' + str(source['Id'])
                row = rows.setdefault(identity, {'id': identity, 'target_id': None,
                    'name': source.get('Domain') or source.get('InstanceId'), 'domain': source.get('Domain'),
                    'kind': source.get('CloudProduct'), 'destination': {'product': source.get('CloudProduct'),
                        'resource_id': source.get('InstanceId') or source.get('Domain'), 'machine': '',
                        'address': '', 'port': source.get('ListenerPort') or 443, 'region': source.get('RegionId') or '全局',
                        'cloud_scope': source.get('Domain'), 'required_domains': [], 'operation': '待核对接入配置'},
                    'binding': 'missing', 'enabled': False, 'excluded': False, 'configuration_required': True,
                    'manual_included': False, 'manual_ready': False, 'manual_reason': '',
                    'automatic_on_new_version': False, 'evidence': [], 'cloud': [], 'tls': None, 'status': {}})
            if 'cloud' not in row['evidence']:
                row['evidence'].append('cloud')
            row['cloud'].append({'resource_id': source['Id'], 'certificate_id': source.get('CertId'),
                'scope': source.get('Domain'), 'version_id': matched.id, 'is_latest': matched.id == certificate.latest_version_id,
                'synced_at': source.get('synced_at')})
        bindings = [r for r in rows.values() if r['binding'] == 'bound']
        unbound = [r for r in rows.values() if r['binding'] != 'bound']
        result.append({'id': certificate.id, 'name': certificate.name, 'domains': certificate.domains,
            'enabled': certificate.enabled, 'auto_deploy': certificate.auto_deploy,
            'latest_version': version_public(latest), 'summary': {'bound': len(bindings),
                'manual': sum(r['manual_included'] for r in bindings), 'automatic': sum(r['automatic_on_new_version'] for r in bindings),
                'cloud': cloud_count, 'observed': sum(bool(r['tls']) for r in rows.values()), 'unbound': len(unbound),
                'skipped': sum(not r['manual_included'] for r in bindings)},
            'bindings': bindings, 'unbound': unbound})
    return {'certificates': result, 'target_status': target_status, 'snapshots': snapshots,
            'metadata_pending': pending, 'generated_at': now()}


def credential_signature(db, identity, visited=None):
    if not identity:
        return None
    visited = visited or set()
    if identity in visited:
        return 'cycle'
    row = db.get(Credential, identity)
    if not row:
        return 'missing'
    return {'id': identity, 'kind': row.kind, 'digest': hashlib.sha256(row.encrypted.encode()).hexdigest(),
            'archived': bool(lifecycle.archived(db, Credential, identity)),
            'jump': credential_signature(db, row.summary.get('jump_credential_id'), visited | {identity})}


def preview(db, certificate, targets, version, purpose, subject):
    credentials = {c.id: c for c in db.scalars(select(Credential))}
    excluded = {e.target_id for e in db.scalars(select(TargetExclusion))}
    included, skipped, manifest = [], [], []
    for target in sorted(targets, key=lambda t: t.id):
        eligible = target.enabled and target.id not in excluded and target.kind != 'monitor'
        reason = deployment_reason(db, certificate, target, version, target.id in excluded)
        row = {'id': target.id, 'name': target.name, 'kind': target.kind, 'domain': target.domain,
               'destination': destination(target, credentials), 'reason': reason}
        (included if eligible else skipped).append(row)
        manifest.append({'id': target.id, 'name': target.name, 'kind': target.kind, 'domain': target.domain, 'region': target.region,
            'config': target.config, 'certificate_id': target.certificate_id, 'enabled': target.enabled,
            'excluded': target.id in excluded, 'auto_deploy': target.auto_deploy,
            'previous_version_id': target.previous_version_id if purpose == 'target_rollback' else None,
            'credential': credential_signature(db, target.credential_id)})
    state = {'purpose': purpose, 'subject': subject, 'certificate_id': certificate.id,
        'certificate_name': certificate.name, 'certificate_domains': certificate.domains,
        'latest_version_id': certificate.latest_version_id,
        'certificate_enabled': certificate.enabled, 'certificate_auto_deploy': certificate.auto_deploy,
        'version_id': version.id if version else None, 'fingerprint': version.fingerprint if version else None,
        'has_private_key': bool(version and version.key_encrypted), 'targets': manifest}
    digest = hashlib.sha256(json.dumps(state, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    token = seal({'purpose': purpose, 'subject': subject, 'digest': digest,
                  'expires': int((now() + timedelta(minutes=10)).timestamp())})
    blockers = [r['name'] + '：' + r['reason'] for r in included if r['reason']]
    if not included:
        blockers.append('没有已启用且绑定的可部署目标')
    return {'certificate': {'id': certificate.id, 'name': certificate.name, 'domains': certificate.domains},
        'version': version_public(version), 'targets': included, 'skipped': skipped,
        'can_submit': bool(included and not blockers), 'blockers': blockers, 'preview_token': token,
        'target_count': len(included), 'purpose': purpose, 'subject': subject, '_digest': digest}


def update_preview(db, certificate):
    targets = list(db.scalars(select(Target).where(Target.certificate_id == certificate.id)))
    plan = preview(db, certificate, targets, None, 'certificate_update', certificate.id)
    automatic = {t.id for t in targets if t.auto_deploy}
    plan['automatic_targets'] = ([{**t, 'reason': ''} for t in plan['targets'] if t['id'] in automatic]
                                 if certificate.enabled and certificate.auto_deploy else [])
    plan['automatic_count'] = len(plan['automatic_targets'])
    # A replacement version is validated only after its PEM and key are provided.
    plan.pop('blockers')
    plan.pop('can_submit')
    return plan


def confirm_preview(token, current):
    try:
        value = unseal(token)
        valid = (value['purpose'] == current['purpose'] and value['subject'] == current['subject']
                 and value['digest'] == current['_digest'] and value['expires'] > now().timestamp())
    except Exception:
        valid = False
    if not valid:
        raise SafeError('预览已过期或版本、绑定及部署配置已变化，请刷新影响范围后重新确认')
