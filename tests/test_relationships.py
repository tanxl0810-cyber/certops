import json
from datetime import timedelta
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tests import test_system as base
from app import relationships
from app.certificates import add_version
from app.cloud_discovery import read_inventory
from app.db import Certificate, Credential, Job, Session, Target, TargetExclusion, Version, now, set_setting
from app.security import seal, unseal
from app.worker import auto_deploy, schedule


def tearDownModule():
    base.engine.dispose()


class RelationshipTests(base.BaseTest):
    login = base.ApiTests.login

    def setUp(self):
        super().setUp()
        self.client = TestClient(base.app, base_url='http://127.0.0.1:18090')
        self.client.__enter__()
        self.client.headers['origin'] = 'http://127.0.0.1:18090'
        self.login()
        with Session() as db:
            cloud = Credential(name='cloud', kind='aliyun', encrypted=seal({'access_key_secret':'never-export-this'}))
            flow = Credential(name='flow', kind='yunxiao', encrypted=seal({'token':'never-export-token'}), summary={'organization_id':'org'})
            certificate = Certificate(name='wildcard', auto_deploy=True)
            other = Certificate(name='same domains, different certificate')
            db.add_all([cloud, flow, certificate, other]); db.flush()
            version = add_version(db, certificate, *base.bundle(['*.example.test']))
            other_version = add_version(db, other, *base.bundle(['*.example.test']))
            target = Target(name='Nginx physical host', kind='yunxiao', domain='api.example.test',
                credential_id=flow.id, certificate_id=certificate.id, resource_key='host:api', auto_deploy=True,
                config={'machine_id':'192.0.2.10','pipeline_id':'1000001',
                    'probe_address':'192.0.2.11','certificate_path':'/etc/nginx/cert/example/api.pem',
                    'private_key_path':'/etc/nginx/cert/example/api.key'})
            db.add(target); db.commit()
            self.cloud_id, self.flow_id = cloud.id, flow.id
            self.cert_id, self.other_id, self.target_id = certificate.id, other.id, target.id
            self.version_id, self.other_version_id = version.id, other_version.id
            self.old_pem = version.cert_pem

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def target(self, db, **kwargs):
        self.counter = getattr(self, 'counter', 0) + 1
        values = {'name':'cloud target', 'kind':'fc', 'domain':'api.example.test',
            'credential_id':self.cloud_id,'resource_key':'resource-' + str(self.counter), 'config':{}}
        row = Target(**{**values, **kwargs}); db.add(row); db.flush(); return row

    def graph(self):
        result = self.client.get('/api/relationships')
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def relation(self, identity=None):
        return next(c for c in self.graph()['certificates'] if c['id'] == (identity or self.cert_id))

    def preview(self, collection='certificates', identity=None, action='deploy'):
        identity = identity or (self.cert_id if collection == 'certificates' else self.target_id)
        result = self.client.get(f'/api/{collection}/{identity}/deploy-preview', params={'action':action})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertNotIn('_digest', result.json())
        return result.json()

    def submit(self, plan, collection='certificates', identity=None, action='deploy'):
        identity = identity or (self.cert_id if collection == 'certificates' else self.target_id)
        return self.client.post(f'/api/{collection}/{identity}/{action}', json={'preview_token':plan['preview_token']})

    def assert_no_deploy_jobs(self):
        with Session() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Job).where(Job.kind == 'deploy')), 0)

    def cache(self, db, rows, metadata):
        set_setting(db, 'cloud_inventory:' + self.cloud_id,
            {'resources':rows, 'certificates':metadata, 'synced_at':now().isoformat()})

    def test_fingerprint_identity_links_historical_usage_without_guessing_from_domain_or_name(self):
        with Session() as db:
            old = db.get(Version, self.version_id)
            sha1 = x509.load_pem_x509_certificate(old.cert_pem.encode()).fingerprint(hashes.SHA1()).hex()
            target = self.target(db, observed={'fingerprint':old.fingerprint,'ok':True}, checked_at=now())
            target_id = target.id
            self.cache(db, [{'Id':'cloud-1','CloudProduct':'FC','CertId':123,'CertName':'renamed in cloud',
                'Domain':'api.example.test','RegionId':'cn-shenzhen'}],
                {'123':{'fingerprint':':'.join(sha1[i:i+2] for i in range(0,40,2)).upper()}})
            add_version(db, db.get(Certificate,self.cert_id), *base.bundle(['*.example.test']))
            db.commit()
        row = self.relation()
        self.assertEqual(row['summary']['cloud'], 1)
        usage = next(r for r in row['unbound'] if r['target_id'] == target_id)
        self.assertEqual(set(usage['evidence']), {'tls','cloud'})
        self.assertFalse(usage['cloud'][0]['is_latest'] or usage['tls']['is_latest'])
        self.assertFalse(usage['manual_included'] or usage['automatic_on_new_version'])
        self.assertEqual(self.relation(self.other_id)['summary']['cloud'], 0)

    def test_same_domain_different_leaf_is_not_current_usage_and_other_binding_is_visible(self):
        with Session() as db:
            target = db.get(Target,self.target_id)
            target.certificate_id = self.other_id
            target.observed = {'fingerprint':db.get(Version,self.version_id).fingerprint,'ok':True}
            target.checked_at = now(); db.commit()
        actual = self.relation()['unbound'][0]
        self.assertEqual(actual['binding'], 'other')
        self.assertEqual(actual['bound_certificate_id'], self.other_id)
        self.assertFalse(actual['automatic_on_new_version'])
        other = self.relation(self.other_id)['bindings'][0]
        self.assertIsNone(other['tls'])
        self.assertEqual(other['status']['actual_certificate_id'], self.cert_id)

    def test_counts_separate_enabled_bindings_automation_and_exclusions(self):
        with Session() as db:
            self.target(db, certificate_id=self.cert_id, auto_deploy=False)
            self.target(db, certificate_id=self.cert_id, auto_deploy=True, enabled=False)
            excluded = self.target(db, certificate_id=self.cert_id, auto_deploy=True)
            db.add(TargetExclusion(target_id=excluded.id, reason='fixture', excluded_by='test'))
            self.target(db, certificate_id=self.cert_id, kind='monitor', credential_id=None)
            db.commit()
        counts = self.relation()['summary']
        self.assertEqual((counts['bound'],counts['manual'],counts['automatic'],counts['skipped']), (5,2,1,3))
        with Session() as db:
            db.get(Certificate,self.cert_id).enabled=False; db.commit()
        self.assertEqual(self.relation()['summary']['automatic'],0)

    def test_destinations_include_physical_machine_vip_pipeline_and_paths_without_secrets(self):
        data = self.graph()
        destination = next(c for c in data['certificates'] if c['id']==self.cert_id)['bindings'][0]['destination']
        self.assertEqual((destination['machine'],destination['address'],destination['pipeline_id']),
                         ('192.0.2.10','192.0.2.11','1000001'))
        self.assertEqual(destination['certificate_path'],'/etc/nginx/cert/example/api.pem')
        self.assertEqual(destination['private_key_path'],'/etc/nginx/cert/example/api.key')
        output = json.dumps(data)
        for secret in ('never-export-this','never-export-token','PRIVATE KEY','BEGIN CERTIFICATE','key_encrypted','preview_token'):
            self.assertNotIn(secret, output)

    def test_ssh_and_listener_descriptors_show_actual_update_location(self):
        with Session() as db:
            ssh = Credential(name='ssh',kind='ssh',encrypted=seal({'private_key':'secret'}),summary={'host':'192.0.2.3'})
            db.add(ssh); db.flush()
            target = self.target(db,kind='nginx',credential_id=ssh.id,config={'certificate_path':'/cert.pem','private_key_path':'/key.pem'})
            info=relationships.destination(target,{ssh.id:ssh})
            self.assertEqual(info['machine'],'192.0.2.3')
            target.kind='clb'; target.config={'load_balancer_id':'lb-test','listener_port':8443,'domain_extension_id':'de-test'}
            info=relationships.destination(target,{})
            self.assertEqual((info['resource_id'],info['port'],info['listener_id']),('lb-test',8443,'de-test'))

    def test_cloud_slot_matching_separates_shared_listener_scopes_and_credential_accounts(self):
        with Session() as db:
            ga = self.target(db,kind='ga',config={'listener_id':'lsr-1','cloud_domain':'*.example.test'})
            clb = self.target(db,kind='clb',config={'load_balancer_id':'lb-1','listener_port':443,'cloud_domain':'*.example.test'})
            waf = self.target(db,kind='waf_cloud',config={'resource_instance_id':'ecs-1','cloud_domain':'*.example.test'})
            oss = self.target(db,kind='oss',config={'bucket':'bucket-1'})
            targets=[ga,clb,waf,oss]
            sources=[(ga,{'CloudProduct':'GA','ListenerId':'lsr-1','Domain':'*.example.test'}),
                     (clb,{'CloudProduct':'SLB','InstanceId':'lb-1','ListenerPort':443,'Domain':'*.example.test'}),
                     (waf,{'CloudProduct':'WAF','InstanceId':'ecs-1','Domain':'*.example.test'}),
                     (oss,{'CloudProduct':'OSS','InstanceId':'bucket-1','Domain':'api.example.test'})]
            for expected,source in sources:
                row={**source,'credential_id':self.cloud_id}
                self.assertEqual(relationships.cloud_target(row,targets).id,expected.id)
                self.assertIsNone(relationships.cloud_target({**row,'Domain':'*.different.test'},targets))
                self.assertIsNone(relationships.cloud_target({**row,'credential_id':self.flow_id},targets))

    def test_cloud_resource_without_local_target_is_visible_but_not_deployed(self):
        with Session() as db:
            self.cache(db,[{'Id':'outside','CloudProduct':'OSS','Domain':'assets.example.test','CertId':12,'InstanceId':'bucket'}],
                       {'12':{'fingerprint':db.get(Version,self.version_id).fingerprint}})
            db.commit()
        row=self.relation()['unbound'][0]
        self.assertEqual(row['binding'],'missing')
        self.assertIsNone(row['target_id'])
        self.assertFalse(row['manual_included'] or row['automatic_on_new_version'])

    def test_valid_preview_pins_exact_version_and_omits_stopped_targets(self):
        with Session() as db:
            stopped=self.target(db,certificate_id=self.cert_id,enabled=False)
            stopped_id=stopped.id; db.commit()
        plan=self.preview()
        self.assertTrue(plan['can_submit'])
        self.assertEqual([t['id'] for t in plan['targets']],[self.target_id])
        self.assertEqual([t['id'] for t in plan['skipped']],[stopped_id])
        response=self.submit(plan)
        self.assertEqual(response.status_code,200,response.text)
        with Session() as db:
            jobs=list(db.scalars(select(Job).where(Job.kind=='deploy')))
            self.assertEqual([(j.target_id,j.version_id) for j in jobs],[(self.target_id,self.version_id)])

    def test_preview_rejects_new_latest_version_before_enqueue(self):
        plan=self.preview()
        with Session() as db:
            add_version(db,db.get(Certificate,self.cert_id),*base.bundle(['*.example.test'])); db.commit()
        self.assertEqual(self.submit(plan).status_code,400)
        self.assert_no_deploy_jobs()

    def test_preview_rejects_changed_bindings_paths_and_rotated_credentials(self):
        for change in ('binding','path','credential'):
            with self.subTest(change=change):
                plan=self.preview()
                with Session() as db:
                    if change=='binding':
                        self.target(db,certificate_id=self.cert_id)
                    elif change=='path':
                        target=db.get(Target,self.target_id)
                        target.config={**target.config,'certificate_path':'/another/cert.pem'}
                    else:
                        db.get(Credential,self.flow_id).encrypted=seal({'token':'rotated-token'})
                    db.commit()
                response=self.submit(plan)
                self.assertEqual(response.status_code,400,response.text)
                self.assertIn('预览已过期',response.text)
                self.assert_no_deploy_jobs()

    def test_preview_rejects_expired_or_wrong_action_confirmation(self):
        plan=self.preview()
        token=unseal(plan['preview_token']);token['expires']=int((now()-timedelta(seconds=1)).timestamp())
        plan['preview_token']=seal(token)
        self.assertEqual(self.submit(plan).status_code,400)
        plan=self.preview('targets')
        self.assertEqual(self.submit(plan).status_code,400)
        self.assert_no_deploy_jobs()

    def test_preview_reports_full_shared_domain_blocker(self):
        with Session() as db:
            target=db.get(Target,self.target_id)
            target.config={**target.config,'required_domains':['*.example.test','another.example.com']}
            db.commit()
        plan=self.preview()
        self.assertFalse(plan['can_submit'])
        self.assertIn('another.example.com',' '.join(plan['blockers']))
        self.assertEqual(self.submit(plan).status_code,400)
        self.assert_no_deploy_jobs()

    def test_cross_certificate_rollback_preview_shows_old_certificate_and_pins_it(self):
        with Session() as db:
            target=db.get(Target,self.target_id)
            target.previous_version_id=self.other_version_id
            target.deployed_version_id=self.version_id; db.commit()
        plan=self.preview('targets',action='rollback')
        self.assertEqual(plan['certificate']['id'],self.other_id)
        self.assertEqual(plan['version']['id'],self.other_version_id)
        response=self.submit(plan,'targets',action='rollback')
        self.assertEqual(response.status_code,200,response.text)
        with Session() as db:
            target=db.get(Target,self.target_id)
            self.assertEqual(target.certificate_id,self.other_id)
            self.assertFalse(target.auto_deploy)
            self.assertEqual(db.get(Job,response.json()['job_id']).version_id,self.other_version_id)

    def test_upload_preview_rejects_route_change_without_persisting_a_version(self):
        plan=self.client.get(f'/api/certificates/{self.cert_id}/update-preview').json()
        self.assertEqual(plan['automatic_count'],1)
        with Session() as db:
            db.get(Target,self.target_id).auto_deploy=False; db.commit()
        pem,key=base.bundle(['*.example.test'])
        response=self.client.post(f'/api/certificates/{self.cert_id}/versions',json={
            'cert_pem':pem,'key_pem':key,'impact_token':plan['preview_token']})
        self.assertEqual(response.status_code,400,response.text)
        with Session() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Version)),2)
        self.assert_no_deploy_jobs()

    def test_confirmed_upload_uses_only_the_shown_automatic_targets(self):
        with Session() as db:
            self.target(db,certificate_id=self.cert_id,auto_deploy=False); db.commit()
        plan=self.client.get(f'/api/certificates/{self.cert_id}/update-preview').json()
        self.assertEqual([r['id'] for r in plan['automatic_targets']],[self.target_id])
        pem,key=base.bundle(['*.example.test'])
        response=self.client.post(f'/api/certificates/{self.cert_id}/versions',json={
            'cert_pem':pem,'key_pem':key,'impact_token':plan['preview_token']})
        self.assertEqual(response.status_code,200,response.text)
        with Session() as db:
            jobs=list(db.scalars(select(Job).where(Job.kind=='deploy')))
            self.assertEqual([(j.target_id,j.version_id) for j in jobs],[(self.target_id,response.json()['id'])])

    def test_disabled_certificate_stops_new_version_and_scheduler_auto_deployment(self):
        with Session() as db:
            cert=db.get(Certificate,self.cert_id);cert.enabled=False
            db.flush()
            self.assertEqual(relationships.update_preview(db,cert)['automatic_count'],0)
            auto_deploy(db,cert,db.get(Version,self.version_id));db.commit()
            with patch('app.worker.deliver_pending'):
                schedule(db)
        self.assert_no_deploy_jobs()

    def test_relationship_and_preview_endpoints_require_login(self):
        self.client.cookies.clear()
        for path in ('/api/relationships',f'/api/certificates/{self.cert_id}/deploy-preview',
                     f'/api/certificates/{self.cert_id}/update-preview',f'/api/targets/{self.target_id}/deploy-preview'):
            self.assertEqual(self.client.get(path).status_code,401)


class InventoryMetadataTests(base.BaseTest):
    def test_inventory_keeps_only_public_certificate_metadata_and_uses_real_fingerprint_field(self):
        class Api:
            def rpc(self,*args,**kwargs):
                return {'Data':[], 'Total':0}
            def cas_certificates(self,page):
                return {'CertificateList':[{'CertificateId':123,'CertificateName':'public name',
                    'Domain':'*.example.test','FingerPrint':'AB'*20,'NotAfter':123456,
                    'Key':'must-not-be-cached','Cert':'must-not-be-cached'}]}
        data=read_inventory(Api(),include_certificates=True)
        self.assertEqual(data['certificates']['123']['fingerprint'],'AB'*20)
        self.assertNotIn('must-not-be-cached',json.dumps(data))
