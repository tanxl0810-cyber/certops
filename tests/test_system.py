import json
import os
import pathlib
import tempfile
import unittest
import logging
import base64
import hashlib
import atexit
from urllib.parse import parse_qs, urlsplit
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

temp = tempfile.TemporaryDirectory()
os.environ['DATABASE_URL'] = os.getenv('CERTOPS_TEST_DATABASE_URL', 'sqlite:///' + str(pathlib.Path(temp.name) / 'test.sqlite').replace('\\', '/'))
os.environ['ENCRYPTION_KEY'] = Fernet.generate_key().decode()
password_path = pathlib.Path(temp.name) / 'admin_password'
password_path.write_text('initial-test-password-12345')
os.environ['ADMIN_PASSWORD_FILE'] = str(password_path)
os.environ['PUBLIC_URL'] = 'http://127.0.0.1:18090'

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from app.main import app
from app.db import (Alert, Base, Certificate, Credential, Job, Session, Target, Version,
                    engine, init_db, now)
from app.certificates import add_version, covers, import_certificate_bundle, parse_bundle, validate_deploy
from app.security import SafeError, seal, unseal
from app.worker import enqueue, process_one, run_deploy, run_issue, schedule, Wait
from app.notifications import send_feishu, feishu_payload, evaluate_expiry
from app.sshdeploy import deployment_script
from app.cloud import Aliyun
from app import feishu_auth
from app.db import FeishuIdentity, FeishuLoginAttempt, LoginSession, User
from app.main import OAuthAccessFilter

atexit.register(engine.dispose)

def tearDownModule():
    engine.dispose()


def bundle(domains=None, days=90, key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    domains = domains or ['api.example.test']
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now() - timedelta(days=2))
        .not_valid_after(now() + timedelta(days=days)).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)
        .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode())


class BaseTest(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine)
        init_db()


class CertificateTests(BaseTest):
    def test_private_key_mismatch_rejected(self):
        cert, _ = bundle()
        _, different = bundle()
        with self.assertRaisesRegex(SafeError, '不匹配'):
            parse_bundle(cert, different)

    def test_wildcard_covers_one_label_only(self):
        self.assertTrue(covers(['*.example.com'], 'api.example.com'))
        self.assertFalse(covers(['*.example.com'], 'example.com'))
        self.assertFalse(covers(['*.example.com'], 'deep.api.example.com'))
        self.assertFalse(covers(['*.example.com'], 'api.evil-example.com'))

    def test_expired_and_wrong_domain_cannot_deploy(self):
        with Session() as db:
            c = Certificate(name='old')
            db.add(c); db.flush()
            v = add_version(db, c, *bundle(days=-1))
            with self.assertRaisesRegex(SafeError, '已过期'):
                validate_deploy(v, 'api.example.test')
            fresh = add_version(db, c, *bundle())
            with self.assertRaisesRegex(SafeError, '没有覆盖'):
                validate_deploy(fresh, 'other.example.test')

    def test_version_is_immutable_and_key_is_encrypted(self):
        first = bundle()
        with Session() as db:
            c = Certificate(name='versions')
            db.add(c); db.flush()
            old = add_version(db, c, *first)
            self.assertNotIn('PRIVATE KEY', old.key_encrypted)
            self.assertIn('PRIVATE KEY', unseal(old.key_encrypted))
            same = add_version(db, c, *first)
            self.assertEqual(old.id, same.id)
            new = add_version(db, c, *bundle())
            self.assertNotEqual(old.id, new.id)
            self.assertEqual(c.latest_version_id, new.id)
            self.assertEqual(db.scalar(select(Version).where(Version.id == old.id)).fingerprint, old.fingerprint)


    def test_import_of_historical_version_keeps_latest_and_renewal_configuration(self):
        old_bundle, new_bundle = bundle(), bundle()
        with Session() as db:
            c = Certificate(name='managed certificate', source='aliyun_v2', auto_renew=True, auto_deploy=True,
                            issuer_config={'instance_id': 'cas_dv-cn-example'})
            db.add(c); db.flush()
            old = add_version(db, c, old_bundle[0])
            latest = add_version(db, c, *new_bundle)
            db.commit()
            row, version, status = import_certificate_bundle(db, 'different import name', *old_bundle)
            db.commit()
            self.assertEqual((row.id, version.id, status), (c.id, old.id, 'key_added'))
            self.assertEqual(row.latest_version_id, latest.id)
            self.assertEqual(row.name, 'managed certificate')
            self.assertEqual(row.source, 'aliyun_v2')
            self.assertTrue(row.auto_renew and row.auto_deploy)
            self.assertEqual(row.issuer_config, {'instance_id': 'cas_dv-cn-example'})
            self.assertTrue(version.key_encrypted)
            self.assertEqual(db.scalar(select(func.count()).select_from(Certificate)), 1)
            self.assertEqual(db.scalar(select(func.count()).select_from(Version)), 2)
            self.assertEqual(db.scalar(select(func.count()).select_from(Job)), 0)

    def test_import_keeps_different_certificates_for_the_same_domain(self):
        with Session() as db:
            first, _, _ = import_certificate_bundle(db, 'first', *bundle())
            second, _, status = import_certificate_bundle(db, 'second', *bundle())
            self.assertEqual(first.domains, second.domains)
            self.assertNotEqual(first.id, second.id)
            self.assertEqual(status, 'imported')

    def test_import_validates_private_key_before_reusing_certificate(self):
        cert, key = bundle()
        _, wrong_key = bundle()
        with Session() as db:
            row, _, _ = import_certificate_bundle(db, 'existing', cert, key)
            db.commit()
            with self.assertRaisesRegex(SafeError, '不匹配'):
                import_certificate_bundle(db, 'invalid key', cert, wrong_key)
            self.assertEqual(db.scalar(select(func.count()).select_from(Certificate)), 1)
            self.assertEqual(row.name, 'existing')

    @unittest.skipUnless(engine.dialect.name == 'postgresql', 'Concurrent imports require production PostgreSQL locks')
    def test_concurrent_imports_create_one_certificate(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        certificate_bundle = bundle()
        barrier = Barrier(2)
        def import_one(name):
            with Session() as db:
                barrier.wait(timeout=10)
                row, version, status = import_certificate_bundle(db, name, *certificate_bundle)
                db.commit()
                return row.id, version.id, status
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(import_one, ['first client', 'second client']))
        self.assertEqual(results[0][:2], results[1][:2])
        self.assertEqual({r[2] for r in results}, {'imported', 'existing'})
        with Session() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Certificate)), 1)
            self.assertEqual(db.scalar(select(func.count()).select_from(Version)), 1)


class ApiTests(BaseTest):
    def setUp(self):
        super().setUp()
        self.client = TestClient(app, base_url='http://127.0.0.1:18090')
        self.client.__enter__()
        self.client.headers['origin'] = 'http://127.0.0.1:18090'

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def login(self, change=True):
        result = self.client.post('/api/login', json={'username': 'admin', 'password': 'initial-test-password-12345'})
        self.assertEqual(result.status_code, 200, result.text)
        self.client.headers['x-csrf-token'] = result.json()['csrf']
        if change:
            result = self.client.post('/api/password', json={'current_password': 'initial-test-password-12345',
                'password': 'changed-strong-password-12345'})
            self.assertEqual(result.status_code, 200, result.text)

    def test_auth_and_first_login_password_gate(self):
        self.assertEqual(self.client.get('/api/certificates').status_code, 401)
        self.login(change=False)
        self.assertEqual(self.client.get('/api/dashboard').status_code, 403)
        self.assertEqual(self.client.get('/api/session').status_code, 200)

    def test_csrf_and_origin(self):
        self.login()
        self.client.headers['x-csrf-token'] = 'invalid'
        self.assertEqual(self.client.post('/api/certificates', json={'name': 'x'}).status_code, 403)
        self.client.headers['origin'] = 'https://evil.example'
        self.assertEqual(self.client.post('/api/login', json={'username': 'admin', 'password': 'anything'}).status_code, 403)

    def test_credential_never_returns_secret(self):
        self.login()
        secret = {'access_key_id': 'LTAI-example-not-real', 'access_key_secret': 'sensitive-test-value'}
        created = self.client.post('/api/credentials', json={'name': 'cloud', 'kind': 'aliyun', 'secrets': secret})
        self.assertEqual(created.status_code, 200, created.text)
        self.assertNotIn(secret['access_key_secret'], created.text)
        result = self.client.get('/api/credentials')
        self.assertNotIn(secret['access_key_secret'], result.text)
        self.assertNotIn('encrypted', result.text)
        with Session() as db:
            row = db.get(Credential, created.json()['id'])
            self.assertNotIn(secret['access_key_secret'], row.encrypted)
            self.assertEqual(unseal(row.encrypted)['access_key_secret'], secret['access_key_secret'])

    def test_yunxiao_token_is_encrypted_and_connection_test_only_reads(self):
        self.login()
        secret = {'token': 'pt-fixture-never-real', 'organization_id': 'example-organization',
                  'test_pipeline_id': '1000001'}
        response = self.client.post('/api/credentials', json={'name': 'pipeline', 'kind': 'yunxiao', 'secrets': secret})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn(secret['token'], response.text)
        self.assertNotIn(secret['token'], self.client.get('/api/credentials').text)
        with patch('app.main.Yunxiao.pipeline', return_value={'id': 1000001}) as read:
            checked = self.client.post('/api/credentials/' + response.json()['id'] + '/test', json={})
            self.assertEqual(checked.status_code, 200, checked.text)
            read.assert_called_once_with('1000001')
        with Session() as db:
            row = db.get(Credential, response.json()['id'])
            self.assertNotIn(secret['token'], row.encrypted)
            self.assertEqual(unseal(row.encrypted)['token'], secret['token'])

    def test_upload_bind_and_queue_roundtrip(self):
        self.login()
        cred = self.client.post('/api/credentials', json={'name': 'cloud', 'kind': 'aliyun',
            'secrets': {'access_key_id': 'not-real', 'access_key_secret': 'not-real'}}).json()
        certificate = self.client.post('/api/certificates', json={'name': 'api cert'}).json()
        cert, key = bundle()
        upload = self.client.post(f'/api/certificates/{certificate["id"]}/versions', json={'cert_pem': cert, 'key_pem': key})
        self.assertEqual(upload.status_code, 200, upload.text)
        self.assertNotIn('PRIVATE KEY', upload.text)
        target = self.client.post('/api/targets', json={'name': 'DCDN', 'kind': 'dcdn', 'domain': 'api.example.test',
            'credential_id': cred['id'], 'certificate_id': certificate['id']})
        self.assertEqual(target.status_code, 200, target.text)
        result = self.client.post(f'/api/targets/{target.json()["id"]}/deploy', json={})
        self.assertEqual(result.status_code, 200, result.text)
        again = self.client.post(f'/api/targets/{target.json()["id"]}/deploy', json={})
        self.assertEqual(result.json()['job_id'], again.json()['job_id'])
        self.assertNotIn(key, self.client.get('/api/jobs').text)

    def test_monitor_target_cannot_deploy(self):
        self.login()
        target = self.client.post('/api/targets', json={'name': 'monitor', 'kind': 'monitor', 'domain': 'api.example.test'})
        self.assertEqual(target.status_code, 200)
        result = self.client.post(f'/api/targets/{target.json()["id"]}/deploy', json={})
        self.assertEqual(result.status_code, 400)

    def test_cloud_import_reuses_certificate_across_names_and_credentials_and_adds_key(self):
        self.login()
        credentials = [self.client.post('/api/credentials', json={'name': name, 'kind': 'aliyun',
            'secrets': {'access_key_id': 'not-real', 'access_key_secret': 'not-real'}}).json()
            for name in ['first credential', 'another credential']]
        cert, key = bundle()
        with patch('app.main.Aliyun.cas_download', side_effect=[(cert, ''), (cert.replace('\n', '\r\n'), key), (cert, key)]):
            first = self.client.post('/api/cloud/import', json={'credential_id': credentials[0]['id'],
                'cert_id': 123, 'name': 'original name'})
            self.assertEqual(first.status_code, 200, first.text)
            self.assertEqual(first.json()['import_status'], 'imported')
            self.assertFalse(first.json()['latest_version']['has_private_key'])
            second = self.client.post('/api/cloud/import', json={'credential_id': credentials[1]['id'],
                'cert_id': 456, 'name': 'renamed import'})
            self.assertEqual(second.status_code, 200, second.text)
            self.assertEqual(second.json()['id'], first.json()['id'])
            self.assertEqual(second.json()['name'], 'original name')
            self.assertEqual(second.json()['import_status'], 'key_added')
            self.assertTrue(second.json()['latest_version']['has_private_key'])
            third = self.client.post('/api/cloud/import', json={'credential_id': credentials[0]['id'],
                'cert_id': 123, 'name': 'third import'})
            self.assertEqual(third.status_code, 200, third.text)
            self.assertEqual(third.json()['id'], first.json()['id'])
            self.assertEqual(third.json()['import_status'], 'existing')
            self.assertTrue(third.json()['imported_version_is_latest'])
            self.assertNotIn('PRIVATE KEY', first.text + second.text + third.text)
        with Session() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Certificate)), 1)
            self.assertEqual(db.scalar(select(func.count()).select_from(Version)), 1)

    def test_logout_revokes_session(self):
        self.login()
        self.assertEqual(self.client.post('/api/logout', json={}).status_code, 200)
        self.assertEqual(self.client.get('/api/session').status_code, 401)


class WorkerTests(BaseTest):
    def fixture(self, db):
        cred = Credential(name='cloud', kind='aliyun', encrypted=seal({'access_key_id':'test','access_key_secret':'test'}))
        db.add(cred); db.flush()
        c = Certificate(name='api', source='aliyun_v1', credential_id=cred.id, domains=['api.example.test'],
            issuer_config={'allow_resource_consumption':True,'contact_name':'Test','phone':'13800000000','email':'test@example.test'})
        db.add(c); db.flush()
        return cred,c

    def test_ambiguous_issue_never_spends_quota_twice(self):
        calls=[]
        def rpc(self, service, action, **params):
            calls.append(action)
            raise SafeError('cloud timeout')
        with Session() as db:
            _,c=self.fixture(db)
            job=enqueue(db,'issue',certificate_id=c.id); db.commit()
            with patch.object(Aliyun,'rpc',rpc):
                process_one(db)
                self.assertEqual(job.state,'failed')
                job.state='queued';db.commit()
                process_one(db)
            self.assertEqual(calls.count('CreateCertificateForPackageRequest'),1)
            self.assertIn('结果不明',job.error)

    def test_submitted_deployment_only_resumes_verification(self):
        with Session() as db:
            cred,c=self.fixture(db)
            v=add_version(db,c,*bundle())
            t=Target(name='edge',kind='dcdn',domain='api.example.test',region='cn-hangzhou',resource_key='edge',credential_id=cred.id,certificate_id=c.id)
            db.add(t);db.flush()
            job=enqueue(db,'deploy',c.id,t.id,v.id);job.progress={'submitted':True,'verify_attempt':0};db.commit()
            with patch('app.worker.run_probe',return_value={'fingerprint':v.fingerprint,'ok':True}),patch.object(Aliyun,'apply_target',side_effect=AssertionError('must not submit again')):
                run_deploy(db,job)
            self.assertEqual(t.deployed_version_id,v.id)

    def test_binding_change_stops_queued_deployment(self):
        with Session() as db:
            cred,c=self.fixture(db);v=add_version(db,c,*bundle())
            t=Target(name='edge',kind='dcdn',domain='api.example.test',resource_key='edge',credential_id=cred.id)
            db.add(t);db.flush();job=enqueue(db,'deploy',c.id,t.id,v.id);db.commit()
            with self.assertRaisesRegex(SafeError,'绑定已改变'):
                run_deploy(db,job)

    def test_expiry_alert_is_deduplicated(self):
        from app.db import set_setting
        with Session() as db:
            _,c=self.fixture(db);add_version(db,c,*bundle(days=6))
            set_setting(db,'notifications',{'enabled':True,'days':[30,15,7,3,1]});db.commit()
            evaluate_expiry(db);db.commit();evaluate_expiry(db);db.commit()
            self.assertEqual(len(list(db.scalars(select(Alert)))),1)

    def test_ga_default_and_sni_use_correct_parameters(self):
        captured=[]
        def rpc(service,action,**params):
            captured.append((action,params))
            return {'Protocol':'HTTPS'} if action=='DescribeListener' else {'RequestId':'test'}
        api=Aliyun({'access_key_id':'test','access_key_secret':'test'})
        api.rpc=rpc
        target=Target(name='ga',kind='ga',domain='api.example.test',region='cn-hangzhou',resource_key='ga',
            config={'listener_id':'lsr-test','accelerator_id':'ga-test','certificate_role':'additional'})
        api.apply_target(target,'public','private','fingerprint',{'cas_cert_id':'123','job_id':'abc'},lambda **kw:None)
        action,params=captured[-1]
        self.assertEqual(action,'UpdateAdditionalCertificateWithListener')
        self.assertEqual(params['CertificateId'],'123-cn-hangzhou')
        self.assertEqual(params['Domain'],'api.example.test')
        self.assertNotIn('NewCertificateId',params)

    def test_waf_cloud_preserves_other_sni_certificates(self):
        captured=[]
        def rpc(service,action,**params):
            captured.append((action,params))
            if action=='DescribeCloudResourceAccessPortDetails':
                return {'AccessPortDetails':[{'Port':443,'Protocol':'https','CloudResourceId':'lb-test-443-clb4',
                    'Certificates':[{'CertificateId':'old-cn-hangzhou','AppliedType':'default'},
                                    {'CertificateId':'keep-cn-hangzhou','AppliedType':'extension'}]}]}
            return {'RequestId':'test'}
        api=Aliyun({'access_key_id':'test','access_key_secret':'test'});api.rpc=rpc
        target=Target(name='waf cloud',kind='waf_cloud',domain='api.example.test',region='cn-hangzhou',resource_key='test',
            config={'instance_id':'waf-test','resource_instance_id':'lb-test','resource_product':'clb4',
                    'port':443,'replace_certificate_id':'old-cn-hangzhou'})
        api.apply_target(target,'public','private','fingerprint',{'cas_cert_id':'new','job_id':'abc'},lambda **kw:None)
        action,params=captured[-1]
        self.assertEqual(action,'ModifyCloudResourceCert')
        self.assertEqual(params['Certificates'],[{'CertificateId':'new-cn-hangzhou','AppliedType':'default'},
                                                {'CertificateId':'keep-cn-hangzhou','AppliedType':'extension'}])
        self.assertEqual(target.config['replace_certificate_id'],'new-cn-hangzhou')

    @unittest.skipUnless(os.name=='posix','rollback script is validated in Linux container')
    def test_nginx_failed_reload_restores_original_files(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            cert=pathlib.Path(directory)/'fullchain.pem';key=pathlib.Path(directory)/'privkey.pem'
            cert.write_text('old certificate');key.write_text('old private key')
            pathlib.Path(str(cert)+'.certops-test.tmp').write_text('new certificate')
            pathlib.Path(str(key)+'.certops-test.tmp').write_text('new private key')
            script=deployment_script({'certificate_path':str(cert),'private_key_path':str(key),
                                      'test_command':'true','reload_command':'false'},'test')
            result=subprocess.run(['bash','-c',script],capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(cert.read_text(),'old certificate')
            self.assertEqual(key.read_text(),'old private key')


class NotificationTests(unittest.TestCase):
    def test_http_200_with_feishu_business_error_is_failure(self):
        transport=httpx.MockTransport(lambda req:httpx.Response(200,json={'code':19024,'msg':'bad sign'}))
        with self.assertRaisesRegex(SafeError,'19024'):
            send_feishu({'webhook':'https://open.feishu.cn/open-apis/bot/v2/hook/test'},'test','content',transport=transport)

    def test_signed_message_success(self):
        payloads=[]
        def handler(request):
            payloads.append(json.loads(request.content))
            return httpx.Response(200,json={'code':0})
        send_feishu({'webhook':'https://open.feishu.cn/open-apis/bot/v2/hook/test','sign_secret':'test-sign-secret'},
                    'Expiry','api.example.test',transport=httpx.MockTransport(handler))
        self.assertIn('timestamp',payloads[0])
        self.assertIn('sign',payloads[0])
        self.assertNotIn('test-sign-secret',json.dumps(payloads[0]))


class FeishuTests(BaseTest):
    def setUp(self):
        super().setUp()
        self.env = patch.dict(os.environ, {'PUBLIC_URL': 'https://cert.example.test',
            'FEISHU_APP_ID': 'cli_test', 'FEISHU_APP_SECRET': 'secret-never-log',
            'FEISHU_TENANT_KEY': 'tenant-approved',
            'FEISHU_ALLOWED_OPEN_IDS': 'ou_allowed'})
        self.env.start()
        self.client = TestClient(app, base_url='https://cert.example.test')
        self.client.__enter__()
        self.client.headers['origin'] = 'https://cert.example.test'

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.env.stop()

    def begin(self):
        response = self.client.get('/api/auth/feishu/login', follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        return response, parse_qs(urlsplit(response.headers['location']).query)

    def callback(self, params):
        return self.client.get(feishu_auth.CALLBACK_PATH,
            params={'state': params['state'][0], 'code': 'code-one-use'}, follow_redirects=False)

    def sign_in(self):
        _, params = self.begin()
        with patch.object(feishu_auth, 'exchange', return_value=('ou_allowed', 'tenant-approved', '成员甲')):
            response = self.callback(params)
        self.assertEqual(response.headers['location'], '/')
        return response

    def test_oauth_state_pkce_encryption_and_cookie(self):
        options = self.client.get('/api/auth/options').json()
        self.assertTrue(options['feishu'])
        self.assertNotIn('secret', json.dumps(options))
        response, params = self.begin()
        self.assertEqual(params['redirect_uri'], ['https://cert.example.test/api/auth/feishu/callback'])
        self.assertEqual(params['code_challenge_method'], ['S256'])
        self.assertIn('Secure', response.headers['set-cookie'])
        self.assertIn('HttpOnly', response.headers['set-cookie'])
        self.assertIn('SameSite=lax', response.headers['set-cookie'])
        self.assertEqual(response.headers['referrer-policy'], 'no-referrer')
        with Session() as db:
            attempt = db.scalar(select(FeishuLoginAttempt))
            self.assertNotEqual(attempt.state_hash, params['state'][0])
            verifier = unseal(attempt.verifier_encrypted)
            self.assertNotIn(verifier, attempt.verifier_encrypted)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
            self.assertEqual(params['code_challenge'], [challenge])

    def test_missing_or_wrong_browser_cookie_never_exchanges_code(self):
        _, params = self.begin()
        browser = self.client.cookies.get(feishu_auth.COOKIE_NAME)
        self.client.cookies.clear()
        with patch.object(feishu_auth, 'exchange') as exchange:
            self.assertIn('state_invalid', self.callback(params).headers['location'])
            self.client.cookies.set(feishu_auth.COOKIE_NAME, 'wrong', path=feishu_auth.COOKIE_PATH)
            self.assertIn('state_invalid', self.callback(params).headers['location'])
            exchange.assert_not_called()
        # An unrelated browser cannot consume the legitimate transaction.
        with Session() as db:
            self.assertEqual(len(list(db.scalars(select(FeishuLoginAttempt)))), 1)
        self.client.cookies.clear()
        self.client.cookies.set(feishu_auth.COOKIE_NAME, browser, path=feishu_auth.COOKIE_PATH)
        with patch.object(feishu_auth, 'exchange', return_value=('ou_allowed', 'tenant-approved', '成员甲')):
            self.assertEqual(self.callback(params).headers['location'], '/')

    def test_expired_and_configuration_changed_attempts_are_rejected(self):
        _, params = self.begin()
        with Session() as db:
            attempt = db.scalar(select(FeishuLoginAttempt))
            attempt.expires_at = now() - timedelta(seconds=1)
            db.commit()
        with patch.object(feishu_auth, 'exchange') as exchange:
            self.assertIn('state_invalid', self.callback(params).headers['location'])
            _, params = self.begin()
            with patch.dict(os.environ, {'FEISHU_APP_SECRET': 'rotated-secret'}):
                self.assertIn('state_invalid', self.callback(params).headers['location'])
            exchange.assert_not_called()

    def test_attempt_consumed_once_even_if_provider_fails(self):
        _, params = self.begin()
        browser = self.client.cookies.get(feishu_auth.COOKIE_NAME)
        with patch.object(feishu_auth, 'exchange', side_effect=feishu_auth.LoginError('token_failed')) as exchange:
            self.assertIn('token_failed', self.callback(params).headers['location'])
            self.client.cookies.set(feishu_auth.COOKIE_NAME, browser, path=feishu_auth.COOKIE_PATH)
            self.assertIn('state_invalid', self.callback(params).headers['location'])
            self.assertEqual(exchange.call_count, 1)
        with Session() as db:
            self.assertIsNone(db.scalar(select(FeishuLoginAttempt)))
            self.assertEqual(len(list(db.scalars(select(User)))), 1)

    def test_success_creates_separate_sso_user_and_reuses_identity(self):
        self.sign_in()
        with patch.object(feishu_auth, 'authorized_member', return_value={'name': '成员甲'}):
            session = self.client.get('/api/session').json()
            self.assertEqual(session['provider'], 'feishu')
            self.assertEqual(session['display_name'], '成员甲')
            self.assertFalse(session['must_change'])
            self.client.headers['x-csrf-token'] = session['csrf']
            self.assertEqual(self.client.get('/api/dashboard').status_code, 200)
            self.assertEqual(self.client.post('/api/password', json={
                'current_password': 'x', 'password': 'some-new-password-1234'}).status_code, 403)
            self.assertEqual(self.client.post('/api/logout').status_code, 200)
        self.sign_in()
        with Session() as db:
            self.assertEqual(len(list(db.scalars(select(FeishuIdentity)))), 1)
            self.assertEqual(len(list(db.scalars(select(User)))), 2)
            self.assertTrue(db.scalar(select(User).where(User.username == 'admin')).must_change)

    def test_member_revocation_invalidates_existing_sessions(self):
        self.sign_in()
        with patch.object(feishu_auth, 'authorized_member', side_effect=feishu_auth.LoginError('member_denied')):
            self.assertEqual(self.client.get('/api/session').status_code, 401)
        with Session() as db:
            self.assertIsNone(db.scalar(select(LoginSession)))
        self.assertEqual(self.client.get('/api/dashboard').status_code, 401)

    def test_source_outage_fails_closed_without_disabling_local_admin(self):
        self.sign_in()
        with patch.object(feishu_auth, 'authorized_member', side_effect=feishu_auth.LoginError('authorization_unavailable')):
            self.assertEqual(self.client.get('/api/dashboard').status_code, 503)
            response = self.client.post('/api/login', json={'username': 'admin', 'password': 'initial-test-password-12345'})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(self.client.get('/api/session').status_code, 200)

    def test_sso_mutations_require_origin_and_csrf(self):
        self.sign_in()
        with patch.object(feishu_auth, 'authorized_member', return_value={'name': '成员甲'}):
            self.assertEqual(self.client.post('/api/logout').status_code, 403)
            session = self.client.get('/api/session').json()
            self.client.headers['x-csrf-token'] = session['csrf']
            self.client.headers['origin'] = 'https://evil.example'
            self.assertEqual(self.client.post('/api/logout').status_code, 403)
            self.client.headers['origin'] = 'https://cert.example.test'
            self.assertEqual(self.client.post('/api/logout').status_code, 200)

    def test_v2_token_json_pkce_and_live_membership_check(self):
        requests = []
        def handler(request):
            requests.append(request)
            if request.url == feishu_auth.TOKEN_URL:
                return httpx.Response(200, json={'code': 0, 'access_token': 'transient-user-token'})
            return httpx.Response(200, json={'code': 0, 'data': {
                'open_id': 'ou_allowed', 'tenant_key': 'tenant-approved', 'name': '成员甲'}})
        transport = httpx.MockTransport(handler)
        real_client = httpx.Client
        with patch.object(feishu_auth.httpx, 'Client', side_effect=lambda **kw: real_client(transport=transport, **kw)), \
             patch.object(feishu_auth, 'authorized_member', return_value={'name': '成员甲'}) as member:
            identity = feishu_auth.exchange(feishu_auth.config(), 'code-once', 'pkce-verifier')
        self.assertEqual(identity, ('ou_allowed', 'tenant-approved', '成员甲'))
        self.assertEqual(len(requests), 2)
        payload = json.loads(requests[0].content)
        self.assertEqual(payload['code_verifier'], 'pkce-verifier')
        self.assertEqual(payload['redirect_uri'], 'https://cert.example.test/api/auth/feishu/callback')
        self.assertIn('application/json', requests[0].headers['content-type'])
        self.assertEqual(requests[1].headers['authorization'], 'Bearer transient-user-token')
        member.assert_called_once_with(feishu_auth.config(), 'ou_allowed', 'tenant-approved')

    def test_provider_failure_has_no_fallback_or_secret_in_error(self):
        real_client = httpx.Client
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={'code': 20049, 'msg': 'secret-never-log code-once'})
        with patch.object(feishu_auth.httpx, 'Client', side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw)):
            with self.assertRaisesRegex(feishu_auth.LoginError, '^token_failed$'):
                feishu_auth.exchange(feishu_auth.config(), 'code-once', 'verifier')
        self.assertEqual(len(requests), 1)
        self.assertNotIn('secret-never-log', repr(feishu_auth.config()))

    def test_tenant_and_unknown_member_rejected(self):
        with self.assertRaisesRegex(feishu_auth.LoginError, 'tenant_denied'):
            feishu_auth.authorized_member(feishu_auth.config(), 'ou_allowed', 'another-tenant')
        with self.assertRaisesRegex(feishu_auth.LoginError, 'member_denied'):
            feishu_auth.authorized_member(feishu_auth.config(), 'ou_unknown', 'tenant-approved')

    def test_explicit_allowlist_is_required_and_rechecked_for_sessions(self):
        self.assertEqual(feishu_auth.authorized_member(feishu_auth.config(), 'ou_allowed',
                                                      'tenant-approved'), {'open_id': 'ou_allowed'})
        self.sign_in()
        with patch.dict(os.environ, {'FEISHU_ALLOWED_OPEN_IDS': 'ou_different'}):
            self.assertEqual(self.client.get('/api/session').status_code, 401)
        with patch.dict(os.environ, {'FEISHU_ALLOWED_OPEN_IDS': ''}):
            self.assertIsNone(feishu_auth.config())
            self.assertFalse(self.client.get('/api/auth/options').json()['feishu'])

    def test_local_tunnel_redirects_to_public_https_before_oauth(self):
        with TestClient(app, base_url='http://127.0.0.1:18090') as local:
            response = local.get('/api/auth/feishu/login', follow_redirects=False)
        self.assertEqual(response.headers['location'], 'https://cert.example.test/api/auth/feishu/login')
        self.assertNotIn('set-cookie', response.headers)

    def test_access_logs_remove_authorization_code(self):
        record = logging.LogRecord('uvicorn.access', logging.INFO, '', 1, '%s %s %s %s %s',
            ('client', 'GET', '/api/auth/feishu/callback?code=sensitive&state=secret', '1.1', 303), None)
        OAuthAccessFilter().filter(record)
        self.assertNotIn('sensitive', record.getMessage())
        self.assertNotIn('state=', record.getMessage())

    def test_tls_terminating_gateway_can_forward_http_without_redirect_loop(self):
        with TestClient(app, base_url='http://gateway.example.test') as proxy:
            options = proxy.get('/api/auth/options').json()
            self.assertEqual(options['login_url'], 'https://cert.example.test/api/auth/feishu/login')
            response = proxy.get('/api/auth/feishu/login', follow_redirects=False)
        self.assertEqual(urlsplit(response.headers['location']).netloc, 'accounts.feishu.cn')
        self.assertIn('Secure', response.headers['set-cookie'])
        self.assertIn('https%3A%2F%2Fcert.example.test%2Fapi%2Fauth', response.headers['location'])

    def test_callback_with_rewritten_proxy_host_keeps_canonical_redirect_uri(self):
        _, params = self.begin()
        browser = self.client.cookies.get(feishu_auth.COOKIE_NAME)
        with TestClient(app, base_url='https://gateway.example.test') as proxy, \
             patch.object(feishu_auth, 'exchange', return_value=('ou_allowed', 'tenant-approved', '成员甲')) as exchange:
            proxy.cookies.set(feishu_auth.COOKIE_NAME, browser, path=feishu_auth.COOKIE_PATH)
            response = proxy.get(feishu_auth.CALLBACK_PATH,
                params={'state': params['state'][0], 'code': 'code-once'}, follow_redirects=False)
        self.assertEqual(response.headers['location'], '/')
        self.assertIn('Secure', response.headers['set-cookie'])
        self.assertEqual(exchange.call_args.args[0].callback_url, 'https://cert.example.test/api/auth/feishu/callback')


if __name__ == '__main__':
    unittest.main(verbosity=2)
