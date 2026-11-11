import json
import uuid
from datetime import timedelta
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests import test_system as base
from app import pipeline
from app.certificates import add_version
from app.db import Certificate, Credential, Job, PipelineExecution, PipelineRunner, Session, Target, now
from app.security import SafeError, seal
from app.worker import enqueue
from app.yunxiao import SubmissionUnknown, Yunxiao


def tearDownModule():
    base.engine.dispose()


class PipelineTests(base.BaseTest):
    def setUp(self):
        super().setUp()
        self.client = TestClient(base.app, base_url='http://127.0.0.1:18090')
        self.client.__enter__()
        self.client.headers['origin'] = 'http://127.0.0.1:18090'
        base.ApiTests.login(self)
        self.cert_pem, key = base.bundle()
        with Session() as db:
            cred = Credential(name='pipeline', kind='yunxiao', encrypted=seal({'token': 'pt-test', 'organization_id': 'test-organization'}))
            certificate = Certificate(name='certificate', domains=['api.example.test'])
            db.add_all([cred, certificate]); db.flush()
            version = add_version(db, certificate, self.cert_pem, key)
            target = Target(name='host', kind='yunxiao', domain='api.example.test', region='cn-hangzhou',
                credential_id=cred.id, certificate_id=certificate.id, resource_key='physical-host:api.example.test',
                config={'pipeline_id': '1000001', 'machine_id': 'physical-host',
                        'certificate_path': '/etc/nginx/cert/example.pem', 'private_key_path': '/etc/nginx/cert/example.key'})
            db.add(target); db.flush()
            self.token = pipeline.provision_runner(db, target)
            job = enqueue(db, 'deploy', certificate.id, target.id, version.id)
            db.commit()
            execution = pipeline.prepare_execution(db, job, target)
            self.target_id, self.cert_id, self.version_id, self.job_id = target.id, certificate.id, version.id, job.id
            self.body = {'attempt_id': execution.attempt_id, 'machine_id': 'physical-host', 'pipeline_id': '1000001'}

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def machine_post(self, action, extra=None, token=None):
        return self.client.post('/api/pipeline/jobs/' + self.job_id + '/' + action,
            headers={'Authorization': 'Bearer ' + (token or self.token)}, json={**self.body, **(extra or {})})

    def dispatch(self, status='RUNNING'):
        with patch('app.pipeline.Yunxiao.start', return_value='31') as start, patch('app.pipeline.Yunxiao.run', return_value={'status': status}):
            with Session() as db:
                with self.assertRaises(pipeline.PipelineWait):
                    pipeline.run_job(db, db.get(Job, self.job_id), db.get(Target, self.target_id))
            start.assert_called_once()

    def successful_report(self):
        return {'status': 'succeeded', 'certificate_pem': self.cert_pem, 'trusted': True,
                'nginx_test_ok': True, 'nginx_reload_ok': True, 'health_ok': True}

    def test_browser_session_cannot_download_private_key_and_runner_is_target_scoped(self):
        self.dispatch()
        response = self.client.post('/api/pipeline/jobs/' + self.job_id + '/bundle', json=self.body)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.machine_post('claim', token='wrong-target-token').status_code, 403)
        self.assertEqual(self.machine_post('claim').status_code, 200)
        response = self.machine_post('bundle')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('PRIVATE KEY', response.json()['key_pem'])
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertNotIn('PRIVATE KEY', self.client.get('/api/jobs').text)
        self.assertNotIn(self.token, self.client.get('/api/targets').text)

    def test_download_is_pinned_and_rebinding_revokes_it(self):
        self.dispatch()
        self.assertEqual(self.machine_post('claim').status_code, 200)
        with Session() as db:
            certificate = db.get(Certificate, self.cert_id)
            add_version(db, certificate, *base.bundle())
            db.commit()
        result = self.machine_post('bundle')
        self.assertEqual(result.json()['version_id'], self.version_id)
        with Session() as db:
            db.get(Target, self.target_id).config = {**db.get(Target, self.target_id).config, 'machine_id': 'different-host'}
            db.commit()
        self.assertEqual(self.machine_post('bundle').status_code, 409)

    def test_switch_to_wildcard_uses_existing_runner_and_cross_certificate_rollback(self):
        old_certificate, old_version = self.cert_id, self.version_id
        with Session() as db:
            # Start from a completed deployment, with its actual certificate recorded.
            db.get(Job, self.job_id).state = 'succeeded'
            target = db.get(Target, self.target_id)
            target.deployed_version_id = old_version
            target.observed = {'fingerprint': db.get(base.Version, old_version).fingerprint, 'ok': True,
                               'version_matches': True}
            new = Certificate(name='wildcard')
            wrong = Certificate(name='wrong suffix')
            db.add_all([new, wrong]); db.flush()
            new_pem, new_key = base.bundle(['*.example.test'])
            version = add_version(db, new, new_pem, new_key)
            add_version(db, wrong, *base.bundle(['*.example.com']))
            db.commit(); new_id, new_version, wrong_id = new.id, version.id, wrong.id
        target = self.client.get('/api/targets').json()[0]
        fields = ('name', 'kind', 'domain', 'region', 'resource_key', 'credential_id',
                  'certificate_id', 'config', 'enabled', 'auto_deploy')
        payload = {k: target[k] for k in fields}
        payload['certificate_id'] = wrong_id
        response = self.client.patch('/api/targets/' + self.target_id, json=payload)
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn('覆盖', response.text)
        payload['certificate_id'] = new_id
        response = self.client.patch('/api/targets/' + self.target_id, json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()['observed']['version_matches'])
        result = self.client.post('/api/targets/' + self.target_id + '/deploy', json={})
        self.assertEqual(result.status_code, 200, result.text)
        self.job_id = result.json()['job_id']
        with Session() as db:
            target = db.get(Target, self.target_id)
            execution = pipeline.prepare_execution(db, db.get(Job, self.job_id), target)
            self.body['attempt_id'] = execution.attempt_id
        # Config is frozen during an active deployment, including cross-cert rollback.
        payload['certificate_id'] = old_certificate
        self.assertEqual(self.client.patch('/api/targets/' + self.target_id, json=payload).status_code, 400)
        self.dispatch(status='SUCCESS')
        self.assertEqual(self.machine_post('claim').status_code, 200)
        downloaded = self.machine_post('bundle')
        self.assertEqual(downloaded.status_code, 200, downloaded.text)
        self.assertEqual(downloaded.json()['version_id'], new_version)
        self.assertEqual(downloaded.json()['cert_pem'], new_pem)
        report = {**self.successful_report(), 'certificate_pem': new_pem}
        self.assertEqual(self.machine_post('report', report).status_code, 200)
        with patch('app.pipeline.Yunxiao.run', return_value={'status': 'SUCCESS'}):
            with Session() as db:
                job = db.get(Job, self.job_id)
                pipeline.run_job(db, job, db.get(Target, self.target_id))
                job.state = 'succeeded'; db.commit()
        response = self.client.post('/api/targets/' + self.target_id + '/rollback', json={})
        self.assertEqual(response.status_code, 200, response.text)
        self.job_id = response.json()['job_id']
        with Session() as db:
            target, job = db.get(Target, self.target_id), db.get(Job, self.job_id)
            self.assertEqual((target.certificate_id, job.certificate_id, job.version_id),
                             (old_certificate, old_certificate, old_version))
            self.assertFalse(target.auto_deploy)
            execution = pipeline.prepare_execution(db, job, target)
            self.body['attempt_id'] = execution.attempt_id
        self.dispatch()
        self.assertEqual(self.machine_post('claim').status_code, 200)
        rolled_back = self.machine_post('bundle')
        self.assertEqual(rolled_back.status_code, 200, rolled_back.text)
        self.assertEqual(rolled_back.json()['version_id'], old_version)

    def test_pipeline_success_needs_valid_host_report_and_report_is_immutable(self):
        self.dispatch(status='SUCCESS')
        with Session() as db:
            self.assertIsNone(db.get(Target, self.target_id).deployed_version_id)
        self.assertEqual(self.machine_post('claim').status_code, 200)
        bad = self.successful_report(); bad['nginx_reload_ok'] = False
        self.assertEqual(self.machine_post('report', bad).status_code, 400)
        report = self.successful_report()
        response = self.machine_post('report', report)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(self.machine_post('report', report).json()['duplicate'])
        self.assertEqual(self.machine_post('report', {**report, 'status': 'failed'}).status_code, 409)
        self.assertEqual(self.machine_post('bundle').status_code, 409)
        with patch('app.pipeline.Yunxiao.run', return_value={'status': 'SUCCESS'}):
            with Session() as db:
                pipeline.run_job(db, db.get(Job, self.job_id), db.get(Target, self.target_id))
                target = db.get(Target, self.target_id)
                self.assertEqual(target.deployed_version_id, self.version_id)
                self.assertEqual(target.observed['source'], 'pipeline_local')
                self.assertTrue(target.observed['version_matches'])

    def test_expired_task_and_rotated_runner_key_reject_downloads(self):
        self.dispatch()
        self.assertEqual(self.machine_post('claim').status_code, 200)
        with Session() as db:
            pipeline.provision_runner(db, db.get(Target, self.target_id)); db.commit()
        self.assertEqual(self.machine_post('bundle').status_code, 403)
        with Session() as db:
            self.token = pipeline.provision_runner(db, db.get(Target, self.target_id))
            db.get(PipelineExecution, self.job_id).expires_at = now() - timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.machine_post('bundle').status_code, 410)

    def test_ambiguous_trigger_is_not_submitted_twice(self):
        with patch('app.pipeline.Yunxiao.start', side_effect=SubmissionUnknown('timeout')) as start, \
             patch('app.pipeline.Yunxiao.find_run', return_value=None):
            for _ in range(2):
                with Session() as db:
                    with self.assertRaises(pipeline.PipelineWait):
                        pipeline.run_job(db, db.get(Job, self.job_id), db.get(Target, self.target_id))
            self.assertEqual(start.call_count, 1)

    def test_probe_has_no_private_key_download_and_can_report_an_older_certificate(self):
        with Session() as db:
            db.delete(db.get(PipelineExecution, self.job_id)); db.flush()
            job = db.get(Job, self.job_id); job.kind = 'probe'
            db.commit()
            execution = pipeline.prepare_execution(db, job, db.get(Target, self.target_id))
            self.body['attempt_id'] = execution.attempt_id
        self.dispatch()
        self.assertEqual(self.machine_post('claim').status_code, 200)
        self.assertEqual(self.machine_post('bundle').status_code, 403)
        older, _ = base.bundle()
        report = {'status': 'succeeded', 'certificate_pem': older, 'trusted': True, 'health_ok': True}
        self.assertEqual(self.machine_post('report', report).status_code, 200)
        with patch('app.pipeline.Yunxiao.run', return_value={'status': 'SUCCESS'}):
            with Session() as db:
                pipeline.run_job(db, db.get(Job, self.job_id), db.get(Target, self.target_id))
                self.assertFalse(db.get(Target, self.target_id).observed['version_matches'])
                self.assertIsNone(db.get(Target, self.target_id).deployed_version_id)


class YunxiaoProtocolTests(base.BaseTest):
    def test_configuration_hash_accepts_live_pipeline_config_shape(self):
        content = 'stages:\n  deploy:\n    run: /usr/local/libexec/certops-pipeline.py\n'
        api = Yunxiao({'token': 'pt-fixture', 'organization_id': 'test-organization'},
            httpx.MockTransport(lambda _: httpx.Response(200, json={'pipelineConfig': {'flow': content}})))
        import hashlib
        self.assertEqual(api.configuration_hash('1000001'), hashlib.sha256(content.encode()).hexdigest())

    def test_runtime_parameters_contain_no_secret_and_run_is_queried(self):
        seen = []
        def upstream(request):
            seen.append(request)
            self.assertEqual(request.url.host, 'openapi-rdc.aliyuncs.com')
            self.assertEqual(request.headers['x-yunxiao-token'], 'pt-fixture')
            if request.method == 'POST':
                body = json.loads(request.content)
                params = json.loads(body['params'])
                self.assertNotIn('pt-fixture', body['params'])
                self.assertEqual(set(params['envs']), {'CERTOPS_JOB_ID', 'CERTOPS_ATTEMPT_ID'})
                return httpx.Response(201, json={'pipelineRunId': 31})
            return httpx.Response(200, json={'status': 'SUCCESS'})
        api = Yunxiao({'token': 'pt-fixture', 'organization_id': 'test-organization'}, httpx.MockTransport(upstream))
        run_id = api.start('1000001', {'CERTOPS_JOB_ID': str(uuid.uuid4()), 'CERTOPS_ATTEMPT_ID': str(uuid.uuid4())})
        self.assertEqual(run_id, '31')
        self.assertEqual(api.run('1000001', run_id)['status'], 'SUCCESS')
        self.assertEqual(len(seen), 2)

    def test_remote_errors_do_not_expose_token_or_body(self):
        api = Yunxiao({'token': 'pt-private', 'organization_id': 'test-organization'},
            httpx.MockTransport(lambda _: httpx.Response(401, text='pt-private secret upstream body')))
        with self.assertRaises(SafeError) as caught:
            api.pipeline('1000001')
        self.assertNotIn('pt-private', str(caught.exception))
        self.assertNotIn('upstream body', str(caught.exception))
