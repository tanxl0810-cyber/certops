from concurrent.futures import ThreadPoolExecutor
import threading
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from fastapi import HTTPException
from sqlalchemy import func, select
from tests import test_system as base
from app import lifecycle
from app.certificates import add_version, import_certificate_bundle
from app.db import (Certificate, Credential, Job, ResourceArchive, Session, Target, Version,
                    set_setting)
from app.main import TargetInput, save_target
from app.security import SafeError, seal, unseal
from app.worker import enqueue, schedule


def tearDownModule():
    base.engine.dispose()


class LifecycleTests(base.BaseTest):
    login = base.ApiTests.login

    def setUp(self):
        super().setUp()
        self.client = TestClient(base.app, base_url='http://127.0.0.1:18090')
        self.client.__enter__()
        self.client.headers['origin'] = 'http://127.0.0.1:18090'
        self.login()

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def credential(self, name='cloud'):
        result = self.client.post('/api/credentials', json={'name': name, 'kind': 'aliyun',
            'secrets': {'access_key_id': 'fixture-only', 'access_key_secret': 'fixture-secret'}})
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()['id']

    def certificate(self, name='certificate', domains=None, **kwargs):
        pem, key = base.bundle(domains)
        with Session() as db:
            row = Certificate(name=name, **kwargs)
            db.add(row); db.flush()
            version = add_version(db, row, pem, key)
            db.commit()
            return row.id, version.id, pem, key

    def test_delete_requires_auth_csrf_and_origin(self):
        identity = self.credential()
        self.client.headers['x-csrf-token'] = 'invalid'
        self.assertEqual(self.client.delete('/api/credentials/' + identity).status_code, 403)
        self.client.cookies.clear()
        self.assertEqual(self.client.delete('/api/credentials/' + identity).status_code, 401)
        self.assertEqual(self.client.get('/api/trash').status_code, 401)
        with Session() as db:
            self.assertIsNone(db.get(ResourceArchive, ('credential', identity)))

    def test_certificate_archive_preserves_history_and_restore_keeps_automation_off(self):
        identity, version_id, pem, key = self.certificate(auto_renew=True, auto_deploy=True)
        with Session() as db:
            job = Job(kind='issue', certificate_id=identity, state='failed')
            db.add(job); db.commit(); job_id = job.id
        result = self.client.delete('/api/certificates/' + identity)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(self.client.delete('/api/certificates/' + identity).status_code, 200)
        self.assertEqual(self.client.get('/api/certificates').json(), [])
        self.assertEqual(self.client.get('/api/dashboard').json()['certificates'], 0)
        self.assertEqual(self.client.post('/api/jobs/' + job_id + '/retry', json={}).status_code, 400)
        self.assertEqual(self.client.post('/api/certificates/' + identity + '/versions',
            json={'cert_pem': pem, 'key_pem': key}).status_code, 410)
        with Session() as db:
            version = db.get(Version, version_id)
            self.assertEqual(unseal(version.key_encrypted), base.parse_bundle(pem, key)[1])
            self.assertEqual(db.get(Job, job_id).state, 'failed')
            with self.assertRaisesRegex(SafeError, '回收站'):
                import_certificate_bundle(db, 'same cert', pem, key)
            schedule(db)
            self.assertEqual(db.scalar(select(func.count()).select_from(Job)), 1)
        trash = self.client.get('/api/trash')
        self.assertNotIn('PRIVATE KEY', trash.text)
        self.assertNotIn('encrypted', trash.text)
        self.assertEqual(trash.json()[0]['resource_id'], identity)
        result = self.client.post('/api/trash/certificate/' + identity + '/restore', json={})
        self.assertEqual(result.status_code, 200, result.text)
        row = self.client.get('/api/certificates').json()[0]
        self.assertEqual(row['latest_version']['id'], version_id)
        self.assertFalse(row['enabled'] or row['auto_renew'] or row['auto_deploy'])

    def test_deleted_credential_cannot_be_used_and_can_be_restored(self):
        identity = self.credential()
        self.assertEqual(self.client.delete('/api/credentials/' + identity).status_code, 200)
        self.assertEqual(self.client.get('/api/credentials').json(), [])
        self.assertNotIn('fixture-secret', self.client.get('/api/trash').text)
        with patch('app.main.Aliyun.rpc') as cloud:
            self.assertEqual(self.client.post('/api/credentials/' + identity + '/test', json={}).status_code, 410)
            cloud.assert_not_called()
        data = {'name': 'issuer', 'source': 'aliyun_v2', 'domains': ['api.example.test'],
                'credential_id': identity}
        self.assertEqual(self.client.post('/api/certificates', json=data).status_code, 400)
        self.assertEqual(self.client.post('/api/targets', json={'name': 'cdn', 'kind': 'dcdn',
            'domain': 'api.example.test', 'credential_id': identity}).status_code, 400)
        self.assertEqual(self.client.post('/api/trash/credential/' + identity + '/restore', json={}).status_code, 200)
        self.assertEqual(self.client.post('/api/certificates', json=data).status_code, 200)

    def test_disabled_references_and_dns_credentials_prevent_deletion(self):
        identity = self.credential()
        with Session() as db:
            db.add_all([Certificate(name='issuer', credential_id=identity, enabled=False),
                Certificate(name='DNS only', enabled=False, issuer_config={'dns_credential_id': identity}),
                Target(name='stopped target', kind='dcdn', domain='api.example.test', enabled=False,
                       credential_id=identity, resource_key='disabled')])
            db.commit()
        preview = self.client.get('/api/credentials/' + identity + '/deletion-check').json()
        self.assertFalse(preview['can_delete'])
        self.assertEqual({r['name'] for r in preview['blockers']}, {'issuer', 'DNS only', 'stopped target'})
        self.assertEqual(self.client.delete('/api/credentials/' + identity).status_code, 409)
        self.assertEqual(len(self.client.get('/api/credentials').json()), 1)

    def test_jump_credentials_and_notification_rules_prevent_deletion(self):
        with Session() as db:
            jump = Credential(name='jump', kind='ssh', encrypted=seal({}))
            webhook = Credential(name='bot', kind='feishu', encrypted=seal({}))
            db.add_all([jump, webhook]); db.flush()
            db.add(Credential(name='private host', kind='ssh', encrypted=seal({'jump_credential_id': jump.id}),
                              summary={'jump_credential_id': jump.id}))
            set_setting(db, 'notifications', {'enabled': False, 'credential_id': webhook.id})
            db.commit(); jump_id, webhook_id = jump.id, webhook.id
        for identity in (jump_id, webhook_id):
            result = self.client.delete('/api/credentials/' + identity)
            self.assertEqual(result.status_code, 409, result.text)
            self.assertEqual(len(result.json()['blockers']), 1)

    def test_deployed_and_rollback_versions_prevent_certificate_deletion(self):
        old_id, version_id, _, _ = self.certificate('old')
        new_id, _, _, _ = self.certificate('new', ['*.example.test'])
        with Session() as db:
            target = Target(name='host with rollback', kind='monitor', domain='api.example.test',
                            certificate_id=new_id, previous_version_id=version_id, resource_key='host', enabled=False)
            db.add(target); db.commit(); target_id = target.id
        result = self.client.delete('/api/certificates/' + old_id)
        self.assertEqual(result.status_code, 409, result.text)
        self.assertIn('回退版本', result.json()['blockers'][0]['reason'])
        with Session() as db:
            t = db.get(Target, target_id)
            t.previous_version_id, t.deployed_version_id = None, version_id
            db.commit()
        self.assertEqual(self.client.delete('/api/certificates/' + old_id).status_code, 409)

    def test_active_jobs_block_deletion_and_failed_jobs_cannot_reuse_deleted_resources(self):
        credential = self.credential()
        certificate, _, _, _ = self.certificate()
        with Session() as db:
            issue = enqueue(db, 'issue', certificate_id=certificate)
            discovery = enqueue(db, 'discover', args={'credential_id': credential})
            db.commit(); job_ids = (issue.id, discovery.id)
        for collection, identity in [('credentials', credential), ('certificates', certificate)]:
            self.assertEqual(self.client.delete('/api/' + collection + '/' + identity).status_code, 409)
        with Session() as db:
            for job_id in job_ids:
                db.get(Job, job_id).state = 'failed'
            db.commit()
        for collection, identity in [('credentials', credential), ('certificates', certificate)]:
            self.assertEqual(self.client.delete('/api/' + collection + '/' + identity).status_code, 200)
        for job_id in job_ids:
            self.assertEqual(self.client.post('/api/jobs/' + job_id + '/retry', json={}).status_code, 400)

    def test_restore_requires_restoring_deleted_dependency_first(self):
        credential = self.credential()
        certificate, _, _, _ = self.certificate(credential_id=credential)
        for collection, identity in [('certificates', certificate), ('credentials', credential)]:
            self.assertEqual(self.client.delete('/api/' + collection + '/' + identity).status_code, 200)
        self.assertEqual(self.client.post('/api/trash/certificate/' + certificate + '/restore', json={}).status_code, 400)
        for kind, identity in [('credential', credential), ('certificate', certificate)]:
            self.assertEqual(self.client.post('/api/trash/' + kind + '/' + identity + '/restore', json={}).status_code, 200)

    @unittest.skipUnless(base.engine.dialect.name == 'postgresql', 'Reference/delete race needs PostgreSQL locks')
    def test_concurrent_deletion_and_new_binding_cannot_create_hidden_reference(self):
        identity, _, _, _ = self.certificate()
        removed, attempted = threading.Event(), threading.Event()
        def remove():
            with Session() as db:
                self.assertEqual(lifecycle.archive(db, 'certificate', identity, 'test'), [])
                removed.set()
                self.assertTrue(attempted.wait(5))
                db.commit()
        def bind():
            self.assertTrue(removed.wait(5))
            with Session() as db:
                attempted.set()
                with self.assertRaises(HTTPException) as rejected:
                    save_target(db, TargetInput(name='racing target', kind='monitor',
                        domain='api.example.test', certificate_id=identity))
                self.assertEqual(rejected.exception.status_code, 410)
                self.assertIn('回收站', rejected.exception.detail)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(remove), pool.submit(bind)]
            for future in futures:
                future.result(timeout=15)
        with Session() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Target)), 0)
