"""Regression checks for the pre-publication security review findings."""
import json
import secrets
import threading
import unittest
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import MagicMock, patch

import httpx
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from .test_system import BaseTest, bundle
from app import security, pipeline_client
from app.db import Alert, Certificate, Credential, Job, Session, Setting, Target, now
from app.certificates import add_version
from app.notifications import add_alert
from app.security import SafeError, consume_rate_limit, seal
from app.main import app
from app.worker import auto_deploy, enqueue, run_deploy, run_probe, schedule


class RedactionTests(unittest.TestCase):
    def test_credential_variants_and_quoted_values_are_removed(self):
        secret = secrets.token_urlsafe(30)
        for name in ('access_key_secret', 'AccessKeySecret', 'private_key', 'passphrase',
                     'sign_secret', 'clientSecret', 'access_token', 'x-yunxiao-token'):
            cases = [f'{name}: {secret}', f'"{name}": "{secret} with spaces"',
                         f"'{name}': '{secret} with spaces'",
                         f'{name}: prefix {secret} with spaces',
                         json.dumps({name: f'prefix "{secret}" with spaces'}),
                         f"{name}='prefix \\'{secret}\\' with spaces'",
                         repr({name: f"prefix '\"{secret}\"' with spaces"})]
            nested = json.dumps({name: f'prefix "{secret}" with spaces'})
            for _ in range(3):
                nested = json.dumps(nested)
                cases.append(nested)
            for text in cases:
                with self.subTest(name=name, quoted='spaces' in text):
                    self.assertNotIn(secret, security.clean_error(text))
                    self.assertNotIn('with spaces', security.clean_error(text))

    def test_authorization_and_connection_passwords_are_removed(self):
        secret = secrets.token_urlsafe(30)
        for text in ('Authorization: Bearer ' + secret, 'Bearer ' + secret,
                     'Authorization: Basic ' + secret,
                     'postgresql+psycopg://service:' + secret + '@db/certops'):
            self.assertNotIn(secret, security.clean_error(text))

    def test_truncated_private_key_is_redacted_before_error_truncation(self):
        secret = secrets.token_urlsafe(30)
        text = 'failed ' + '-----BEGIN RSA PRIVATE KEY-----\n' + secret
        self.assertNotIn(secret, security.clean_error(text))
        self.assertLessEqual(len(security.clean_error(text * 30)), 700)
        self.assertIn('RequestId: example-request', security.clean_error('Forbidden RequestId: example-request'))

    def test_password_work_has_a_bounded_capacity(self):
        slots = threading.BoundedSemaphore(1)
        with patch.object(security, '_password_slots', slots), patch.object(security, 'passwords', MagicMock(verify=MagicMock(return_value=True))):
            slots.acquire()
            try:
                with self.assertRaises(HTTPException) as result:
                    security.verify_password('unused', 'unused')
                self.assertEqual(result.exception.status_code, 429)
            finally:
                slots.release()
            self.assertTrue(security.verify_password('unused', 'unused'))


class RateLimitTests(BaseTest):
    def test_concurrent_new_counter_never_accepts_more_than_the_limit(self):
        barrier = threading.Barrier(12)

        def attempt(_):
            with Session() as db:
                barrier.wait(timeout=10)
                try:
                    consume_rate_limit(db, 'concurrent-review-limit', 5, 900, 'limited')
                    return 200
                except HTTPException as error:
                    return error.status_code

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(attempt, range(12)))
        self.assertEqual(results.count(200), 5)
        self.assertEqual(results.count(429), 7)
        with Session() as db:
            self.assertEqual(db.get(Setting, 'concurrent-review-limit').value['count'], 5)

    def test_expired_window_resets_and_success_can_reset(self):
        with Session() as db:
            consume_rate_limit(db, 'window-review-limit', 1, 900, 'limited', timestamp=1000)
            with self.assertRaises(HTTPException):
                consume_rate_limit(db, 'window-review-limit', 1, 900, 'limited', timestamp=1001)
            consume_rate_limit(db, 'window-review-limit', 1, 900, 'limited', timestamp=2000)
            security.reset_rate_limit(db, 'window-review-limit')
            self.assertEqual(db.get(Setting, 'window-review-limit').value['count'], 0)


class ApiHardeningTests(BaseTest):
    def setUp(self):
        super().setUp()
        self.client = TestClient(app, base_url='http://127.0.0.1:18090')
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.client.headers['Origin'] = 'http://127.0.0.1:18090'

    def test_failed_logins_are_limited_before_password_work(self):
        with patch('app.main.verify_password', return_value=False) as verify:
            for _ in range(10):
                self.assertEqual(self.client.post('/api/login', json={'username': 'admin', 'password': 'wrong'}).status_code, 401)
            self.assertEqual(self.client.post('/api/login', json={'username': 'admin', 'password': 'wrong'}).status_code, 429)
            self.assertEqual(verify.call_count, 10)

    def test_successful_login_resets_failure_counter_and_busy_verifier_is_429(self):
        for _ in range(2):
            with patch('app.main.verify_password', return_value=False):
                self.assertEqual(self.client.post('/api/login', json={'username': 'admin', 'password': 'wrong'}).status_code, 401)
        with patch('app.main.verify_password', return_value=True):
            self.assertEqual(self.client.post('/api/login', json={'username': 'admin', 'password': 'valid'}).status_code, 200)
        with Session() as db:
            rows = list(db.scalars(select(Setting).where(Setting.key.like('login-%'))))
            self.assertTrue(rows)
            self.assertTrue(all(row.value['count'] == 0 for row in rows))
        with patch('app.main.verify_password', side_effect=HTTPException(429, 'busy')):
            self.assertEqual(self.client.post('/api/login', json={'username': 'admin', 'password': 'valid'}).status_code, 429)

    def test_oversized_stream_is_rejected_even_without_or_with_a_false_length(self):
        payload = json.dumps({'username': 'admin', 'password': 'x' * 450000}).encode()
        for length in (None, '1', str(len(payload))):
            headers = {'Content-Type': 'application/json'}
            if length is not None:
                headers['Content-Length'] = length
            response = self.client.post('/api/login', content=iter([payload[:200000], payload[200000:]]), headers=headers)
            self.assertEqual(response.status_code, 413)
            self.assertIn('Content-Security-Policy', response.headers)

    def test_small_stream_is_replayed_correctly_and_invalid_length_is_400(self):
        payload = json.dumps({'username': 'admin', 'password': 'initial-test-password-12345'}).encode()
        response = self.client.post('/api/login', content=iter([payload[:10], payload[10:]]), headers={'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/api/login', content=b'{}', headers={'Content-Length': 'invalid'})
        self.assertEqual(response.status_code, 400)


class RecoveryAndSubmissionTests(BaseTest):
    def deployment(self, db):
        cert = Certificate(name='review certificate')
        credential = Credential(name='review cloud', kind='aliyun', encrypted=seal({'access_key_id': 'fixture', 'access_key_secret': 'fixture'}))
        db.add_all([cert, credential]); db.flush()
        version = add_version(db, cert, *bundle())
        target = Target(name='review target', kind='dcdn', domain='api.example.test', resource_key='api.example.test',
                        credential_id=credential.id, certificate_id=cert.id)
        db.add(target); db.flush()
        job = enqueue(db, 'deploy', cert.id, target.id, version.id)
        db.commit()
        return target, version, job

    def test_long_alert_keys_fit_the_column_and_still_deduplicate(self):
        key = 'recovery:' + 't' * 36 + ':' + 'e' * 700 + ':' + 'f' * 64
        with Session() as db:
            add_alert(db, key, 'Recovery', 'Recovered')
            add_alert(db, key, 'Recovery', 'Recovered')
            db.commit()
            rows = list(db.scalars(select(Alert)))
            self.assertEqual(len(rows), 1)
            self.assertLessEqual(len(rows[0].dedupe_key), Alert.__table__.c.dedupe_key.type.length)

    def test_probe_can_recover_from_a_long_previous_error(self):
        with Session() as db:
            target = Target(name='probe review', kind='monitor', domain='api.example.test', resource_key='probe-review',
                            observed={'ok': False, 'error': 'e' * 700})
            db.add(target); db.commit()
            with patch('app.worker.probe', return_value={'ok': True, 'fingerprint': 'f' * 64}):
                result = run_probe(db, target)
            self.assertTrue(result['ok'])
            self.assertEqual(db.scalar(select(func.count()).select_from(Alert)), 1)

    def test_uncertain_cloud_write_is_never_blindly_repeated(self):
        with Session() as db:
            target, version, job = self.deployment(db)
            with patch('app.worker.Aliyun.apply_target', side_effect=TimeoutError('simulated')) as write:
                with self.assertRaises(TimeoutError):
                    run_deploy(db, job)
                db.rollback()
                self.assertTrue(db.get(Job, job.id).progress['submission_started'])
                with patch('app.worker.run_probe', return_value={'ok': False}):
                    with self.assertRaisesRegex(SafeError, '停止自动重发'):
                        run_deploy(db, db.get(Job, job.id))
                self.assertEqual(write.call_count, 1)

    def test_uncertain_cloud_write_can_reconcile_from_the_live_fingerprint(self):
        with Session() as db:
            target, version, job = self.deployment(db)
            job.progress = {'submission_started': True}; db.commit()
            with patch('app.worker.Aliyun.apply_target') as write, patch('app.worker.run_probe', return_value={
                    'ok': True, 'fingerprint': version.fingerprint}):
                run_deploy(db, job)
            write.assert_not_called()
            self.assertEqual(target.deployed_version_id, version.id)
            self.assertTrue(job.progress['reconciled'])

    def test_automatic_creation_stays_blocked_after_the_daily_retry_window(self):
        with Session() as db:
            target, version, old = self.deployment(db)
            certificate = db.get(Certificate, version.certificate_id)
            certificate.auto_deploy = target.auto_deploy = True
            target.checked_at = now()
            old.created_at, old.state = now() - timedelta(hours=25), 'failed'
            old.progress = {'submission_started': True}
            latest = add_version(db, certificate, *bundle()); db.commit()
            auto_deploy(db, certificate, latest)
            with patch('app.worker.deliver_pending'):
                schedule(db)
            self.assertEqual(db.scalar(select(func.count()).select_from(Job).where(Job.kind == 'deploy')), 1)

    def test_already_queued_automatic_deployment_cannot_bypass_an_uncertain_write(self):
        with Session() as db:
            target, version, old = self.deployment(db)
            old.state, old.progress = 'failed', {'submission_started': True}
            queued = enqueue(db, 'deploy', version.certificate_id, target.id, version.id, args={'automatic': True})
            db.commit()
            with patch('app.worker.Aliyun.apply_target') as write:
                with self.assertRaisesRegex(SafeError, '自动部署已暂停'):
                    run_deploy(db, queued)
                write.assert_not_called()

    def test_verified_manual_deployment_allows_later_automation(self):
        with Session() as db:
            target, version, old = self.deployment(db)
            certificate = db.get(Certificate, version.certificate_id)
            certificate.auto_deploy = target.auto_deploy = True
            old.created_at, old.state = now() - timedelta(hours=25), 'failed'
            old.progress = {'submission_started': True}
            manual = enqueue(db, 'deploy', certificate.id, target.id, version.id); db.commit()
            with patch('app.worker.Aliyun.apply_target', return_value={}), patch('app.worker.run_probe',
                    return_value={'ok': True, 'fingerprint': version.fingerprint}):
                run_deploy(db, manual)
            manual.state = 'succeeded'; db.commit()
            latest = add_version(db, certificate, *bundle())
            auto_deploy(db, certificate, latest); db.commit()
            queued = db.scalar(select(Job).where(Job.version_id == latest.id))
            self.assertIsNotNone(queued)
            self.assertTrue(queued.args['automatic'])

    def test_failed_submission_keeps_the_old_rollback_until_reconciliation(self):
        with Session() as db:
            target, oldest, job = self.deployment(db)
            cert = db.get(Certificate, oldest.certificate_id)
            previous = add_version(db, cert, *bundle())
            latest = add_version(db, cert, *bundle())
            target.deployed_version_id, target.previous_version_id = previous.id, oldest.id
            job.version_id = latest.id; db.commit()
            with patch('app.worker.Aliyun.apply_target', side_effect=TimeoutError('simulated')):
                with self.assertRaises(TimeoutError):
                    run_deploy(db, job)
            db.rollback()
            self.assertEqual(target.previous_version_id, oldest.id)
            with patch('app.worker.run_probe', return_value={'ok': True, 'fingerprint': latest.fingerprint}):
                run_deploy(db, job)
            self.assertEqual(target.previous_version_id, previous.id)
            self.assertEqual(target.deployed_version_id, latest.id)

    def test_worker_health_redirect_is_not_a_success(self):
        with Session() as db:
            target, version, job = self.deployment(db)
            target.config = {'health_url': 'https://service.example.test/health'}
            job.progress = {'submitted': True}; db.commit()
            client = httpx.Client
            with patch('app.worker.run_probe', return_value={'ok': True, 'fingerprint': version.fingerprint}), patch(
                    'app.worker.httpx.Client', side_effect=lambda **kwargs: client(transport=httpx.MockTransport(
                        lambda request: httpx.Response(302, headers={'Location': 'https://other.example.test/'})), **kwargs)):
                with self.assertRaisesRegex(SafeError, '健康检查'):
                    run_deploy(db, job)


class PipelineHealthTests(unittest.TestCase):
    def test_client_health_redirect_is_rejected_without_urlopen_fallback(self):
        opener = MagicMock()
        opener.open.side_effect = urllib.error.HTTPError('https://service.example.test/', 302, 'Found', {}, None)
        with patch.object(pipeline_client.urllib.request, 'build_opener', return_value=opener) as factory, patch.object(
                pipeline_client.urllib.request, 'urlopen') as fallback:
            with self.assertRaises(pipeline_client.LocalFailure) as result:
                pipeline_client.health_check({'health_url': 'https://service.example.test/health'})
            self.assertEqual(result.exception.code, 'HEALTH_FAILED')
        self.assertTrue(any(isinstance(handler, pipeline_client.NoRedirect) for handler in factory.call_args.args))
        fallback.assert_not_called()


if __name__ == '__main__':
    unittest.main()
