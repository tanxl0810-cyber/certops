from unittest.mock import patch
from datetime import timedelta
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from tests import test_system as base
from app import exclusions, pipeline
from app.db import (Alert, Certificate, Credential, Job, Session, Target, TargetExclusion,
                    now, set_setting)
from app.certificates import add_version
from app.security import SafeError, seal
from app.worker import auto_deploy, enqueue, run_discover, run_probe, schedule


def tearDownModule():
    base.engine.dispose()


class ExclusionTests(base.BaseTest):
    login = base.ApiTests.login

    def setUp(self):
        super().setUp()
        self.client = TestClient(base.app, base_url='http://127.0.0.1:18090')
        self.client.__enter__()
        self.client.headers['origin'] = 'http://127.0.0.1:18090'
        self.login()
        with Session() as db:
            cred = Credential(name='cloud', kind='aliyun', encrypted=seal({
                'access_key_id': 'fixture', 'access_key_secret': 'never-real'}))
            db.add(cred); db.commit(); self.credential_id = cred.id

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def target(self, **kwargs):
        values = {'name': 'business target', 'kind': 'fc', 'domain': 'api.example.test',
                  'credential_id': self.credential_id, 'resource_key': 'fixture', 'auto_deploy': False}
        with Session() as db:
            row = Target(**{**values, **kwargs})
            db.add(row); db.commit(); return row.id

    def exclude(self, identity, reason='非业务目标'):
        return self.client.post('/api/targets/' + identity + '/exclude', json={'reason': reason})

    def scan(self, rows):
        with Session() as db:
            job = Job(kind='discover', args={'credential_id': self.credential_id,
                'products': ['fc'], 'regions': ['cn-shenzhen']})
            db.add(job); db.commit()
            with patch('app.worker.discover', return_value=(rows, [])):
                run_discover(db, job)
            job.state = 'succeeded'; db.commit()
            return job.progress

    @staticmethod
    def discovered(domain, kind='fc'):
        return {'name': domain, 'domain': domain, 'kind': kind, 'region': 'cn-shenzhen',
                'resource_key': 'cn-shenzhen:' + domain, 'config': {'api_version': '2023-03-30'}}

    def test_exclude_and_restore_require_auth_and_csrf(self):
        identity = self.target()
        self.client.headers['x-csrf-token'] = 'wrong'
        self.assertEqual(self.exclude(identity).status_code, 403)
        self.assertEqual(self.client.post('/api/targets/' + identity + '/include', json={}).status_code, 403)
        self.client.cookies.clear()
        self.assertEqual(self.exclude(identity).status_code, 401)
        with Session() as db:
            self.assertIsNone(db.get(TargetExclusion, identity))

    def test_exclusion_preserves_history_and_stops_actions_retry_and_pending_notifications(self):
        identity = self.target(observed={'ok': True, 'fingerprint': 'original-fingerprint'})
        with Session() as db:
            job = Job(kind='probe', target_id=identity, state='failed')
            db.add(job); db.flush(); job_id = job.id
            keys = ['expiry:target:' + identity + ':fingerprint:7:date',
                    'recovery:' + identity + ':old:new', 'job-failed:' + job_id + ':1', 'unrelated-alert']
            for key in keys:
                db.add(Alert(dedupe_key=key, title='fixture', content='fixture'))
            db.commit()
        result = self.exclude(identity)
        self.assertEqual(result.status_code, 200, result.text)
        row = result.json()
        self.assertTrue(row['excluded'])
        self.assertFalse(row['enabled'] or row['auto_deploy'])
        self.assertEqual(row['exclusion_reason'], '非业务目标')
        self.assertEqual(row['observed']['fingerprint'], 'original-fingerprint')
        self.assertEqual(self.client.get('/api/dashboard').json()['targets'], 0)
        self.assertEqual(self.client.get('/api/dashboard').json()['excluded_targets'], 1)
        for action in ('probe', 'deploy', 'rollback'):
            self.assertEqual(self.client.post('/api/targets/' + identity + '/' + action, json={}).status_code, 400)
        self.assertEqual(self.client.post('/api/jobs/' + job_id + '/retry', json={}).status_code, 400)
        with Session() as db:
            self.assertEqual(db.get(Job, job_id).state, 'failed')
            alerts = {a.dedupe_key: a.state for a in db.scalars(select(Alert))}
            self.assertEqual([alerts[k] for k in keys], ['cancelled', 'cancelled', 'cancelled', 'pending'])
            with self.assertRaisesRegex(SafeError, '已排除'):
                enqueue(db, 'probe', target_id=identity)
            with patch('app.worker.probe', side_effect=AssertionError('excluded target must not connect')):
                with self.assertRaisesRegex(SafeError, '已排除'):
                    run_probe(db, db.get(Target, identity))

    def test_active_job_prevents_exclusion(self):
        identity = self.target()
        with Session() as db:
            enqueue(db, 'probe', target_id=identity); db.commit()
        result = self.exclude(identity)
        self.assertEqual(result.status_code, 400, result.text)
        self.assertIn('未结束', result.text)
        with Session() as db:
            self.assertIsNone(db.get(TargetExclusion, identity))
            self.assertTrue(db.get(Target, identity).enabled)

    def test_restoring_keeps_automation_off_and_blocked_config_requires_restore(self):
        identity = self.target(auto_deploy=True)
        self.assertEqual(self.exclude(identity).status_code, 200)
        payload = {'name': 'reviewed', 'kind': 'fc', 'domain': 'api.example.test',
                   'resource_key': 'fixture', 'credential_id': self.credential_id, 'enabled': True}
        self.assertEqual(self.client.patch('/api/targets/' + identity, json=payload).status_code, 400)
        result = self.client.post('/api/targets/' + identity + '/include', json={})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertFalse(result.json()['excluded'] or result.json()['enabled'] or result.json()['auto_deploy'])
        self.assertEqual(self.client.patch('/api/targets/' + identity, json=payload).status_code, 200)
        # An idempotent restore cannot disable an already re-enabled target.
        self.assertTrue(self.client.post('/api/targets/' + identity + '/include', json={}).json()['enabled'])
        with Session() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Job)), 0)

    def test_native_fc_domains_auto_excluded_without_matching_business_or_suffix_spoofs(self):
        native = 'sample-function.fcv3.1234567890123456.cn-shenzhen.fc.devsapp.net'
        business = 'api.example.test'
        spoof = 'fc.devsapp.net.evil.example'
        rows = [self.discovered(d) for d in (native, business, spoof)]
        progress = self.scan(rows)
        self.assertEqual((progress['found'], progress['added'], progress['excluded']), (3, 2, 1))
        listed = {t['domain']: t for t in self.client.get('/api/targets').json()}
        self.assertTrue(listed[native]['excluded'])
        self.assertFalse(listed[business]['excluded'] or listed[spoof]['excluded'])
        self.assertEqual(self.client.get('/api/dashboard').json()['targets'], 2)
        native_id = listed[native]['id']
        self.assertEqual(self.scan(rows)['excluded'], 1)
        listed = {t['domain']: t for t in self.client.get('/api/targets').json()}
        self.assertEqual(listed[native]['id'], native_id)
        self.assertEqual(len(listed), 3)
        self.assertTrue(exclusions.provider_domain('fc', native.upper() + '.'))
        self.assertFalse(exclusions.provider_domain('dcdn', native))
        self.assertFalse(exclusions.provider_domain('fc', 'notfc.devsapp.net'))

    def test_manual_exclusion_survives_rediscovery_and_restored_native_stays_managed(self):
        row = self.discovered('custom.example.test')
        native = self.discovered('native.fc.devsapp.net')
        self.scan([row, native])
        listed = {t['domain']: t for t in self.client.get('/api/targets').json()}
        custom_id, native_id = listed[row['domain']]['id'], listed[native['domain']]['id']
        self.assertEqual(self.exclude(custom_id).status_code, 200)
        self.assertEqual(self.scan([row, native])['excluded'], 2)
        self.assertEqual(self.client.post('/api/targets/' + native_id + '/include', json={}).status_code, 200)
        self.assertEqual(self.scan([row, native])['excluded'], 1)
        listed = {t['domain']: t for t in self.client.get('/api/targets').json()}
        self.assertTrue(listed[row['domain']]['excluded'])
        self.assertFalse(listed[native['domain']]['excluded'])
        self.assertFalse(listed[native['domain']]['enabled'])

    def test_exclusion_is_enforced_by_scheduler_alerts_auto_deploy_and_dashboard(self):
        with Session() as db:
            cert = Certificate(name='managed library', auto_deploy=True)
            db.add(cert); db.flush()
            version = add_version(db, cert, *base.bundle(days=5))
            db.commit(); cert_id, version_id = cert.id, version.id
        identity = self.target(certificate_id=cert_id, auto_deploy=True,
            observed={'ok': True, 'days_left': 1, 'not_after': (now() + timedelta(days=1)).isoformat()})
        self.assertEqual(self.exclude(identity).status_code, 200)
        with Session() as db:
            # Even stale flags cannot bypass an exclusion marker.
            target = db.get(Target, identity)
            target.enabled = target.auto_deploy = True
            set_setting(db, 'notifications', {'enabled': True, 'days': [30, 7]})
            db.commit()
            auto_deploy(db, db.get(Certificate, cert_id), db.get(base.Version, version_id))
            schedule(db)
            self.assertEqual(db.scalar(select(func.count()).select_from(Job)), 0)
            self.assertFalse(any(a.dedupe_key.startswith('expiry:target:') for a in db.scalars(select(Alert))))
            self.assertTrue(any(a.dedupe_key.startswith('expiry:library:') for a in db.scalars(select(Alert))))
        self.assertEqual(self.client.get('/api/dashboard').json()['targets'], 0)
        self.assertEqual(self.client.get('/api/certificates').json()[0]['target_count'], 0)
        # Retained bindings and rollback data still protect credential/certificate deletion.
        self.assertEqual(self.client.delete('/api/certificates/' + cert_id).status_code, 409)
        self.assertEqual(self.client.delete('/api/credentials/' + self.credential_id).status_code, 409)

    def test_excluded_pipeline_target_cannot_issue_runner_token(self):
        identity = self.target(kind='yunxiao')
        self.assertEqual(self.exclude(identity).status_code, 200)
        with patch('app.pipeline.Yunxiao.configuration_hash') as cloud:
            response = self.client.post('/api/targets/' + identity + '/pipeline-token', json={})
            self.assertEqual(response.status_code, 400, response.text)
            cloud.assert_not_called()
        with Session() as db:
            with self.assertRaisesRegex(SafeError, '已排除'):
                pipeline.provision_runner(db, db.get(Target, identity))
