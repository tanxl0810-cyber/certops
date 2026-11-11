import json
import unittest
from types import SimpleNamespace
from datetime import timedelta
from unittest.mock import patch
from fastapi.testclient import TestClient
from tests import test_system as base
from app.cloud import Aliyun
from app.cloud_discovery import read_inventory, discover_complex, probe_name
from app.certificates import add_version, validate_target_deploy
from app.db import Session, Certificate, Credential, now, set_setting
from app.security import SafeError, seal
from app.worker import enqueue


class FakeCloud:
    def __init__(self):
        self.calls = []
        self.resources = [
            {'Id': 1, 'CloudProduct': 'GA', 'InstanceId': 'ga-1', 'ListenerId': 'lsr-1', 'CertId': 11, 'Domain': '*.example.test'},
            {'Id': 2, 'CloudProduct': 'WAF', 'InstanceId': 'i-cn', 'CertId': 11, 'Domain': '*.example.test', 'RegionId': 'cn-hangzhou'},
            {'Id': 3, 'CloudProduct': 'WAF', 'InstanceId': 'i-hk', 'CertId': 11, 'Domain': '*.example.test', 'RegionId': 'ap-southeast-1'}]

    def factory(self, secret, region):
        parent = self
        class Api:
            def cas_certificates(self, page=1):
                return {'CertificateList': [{'CertificateId': 11, 'Domain': '*.example.test,example.test'},
                    {'CertificateId': 22, 'Domain': '*.stage.example.test,stage.example.test'}]}
            def rpc(self, service, action, **params):
                parent.calls.append((region, service, action, params))
                if action == 'DescribeDomains' and service == 'alidns':
                    return {'Domains': {'Domain': [{'DomainName': 'example.test'}]}}
                if action == 'DescribeDomainRecords':
                    return {'DomainRecords': {'Record': [
                        {'RR': '_acme-challenge', 'Type': 'CNAME', 'Value': 'skip.invalid'},
                        {'RR': 'api', 'Type': 'A', 'Value': '203.0.113.1'},
                        {'RR': 'foo.stage', 'Type': 'A', 'Value': '203.0.113.1'},
                        {'RR': 'atrust', 'Type': 'CNAME', 'Value': 'ga.provider.example'},
                        {'RR': 'wafcn', 'Type': 'A', 'Value': '203.0.113.2'},
                        {'RR': 'wafhk', 'Type': 'A', 'Value': '203.0.113.3'},
                        {'RR': 'disabled', 'Type': 'A', 'Value': '203.0.113.1', 'Status': 'DISABLE'}]}}
                if action == 'ListAccelerators':
                    return {'Accelerators': [{'AcceleratorId': 'ga-1', 'Name': 'HTTPS', 'DnsName': 'ga.provider.example'}]}
                if action == 'ListListeners':
                    return {'Listeners': [
                        {'ListenerId': 'lsr-1', 'Protocol': 'HTTPS', 'Certificates': [{'Id': '11-cn-hangzhou'}], 'PortRanges': [{'FromPort': 443}]},
                        {'ListenerId': 'lsr-tcp', 'Protocol': 'TCP', 'PortRanges': [{'FromPort': 443}]}]}
                if action == 'DescribeLoadBalancers':
                    return {'LoadBalancers': {'LoadBalancer': [{'LoadBalancerId': 'lb-1', 'LoadBalancerName': 'shared', 'Address': '203.0.113.1'}]}}
                if action == 'DescribeLoadBalancerAttribute':
                    return {'ListenerPortsAndProtocol': {'ListenerPortAndProtocol': [
                        {'ListenerPort': 443, 'ListenerProtocol': 'https'}, {'ListenerPort': 80, 'ListenerProtocol': 'http'}]}}
                if action == 'DescribeLoadBalancerHTTPSListenerAttribute':
                    return {'ServerCertificateId': 'slb-default', 'DomainExtensions': {'DomainExtension': [
                        {'Domain': '*.stage.example.test', 'DomainExtensionId': 'de-1', 'ServerCertificateId': 'slb-stage'}]}}
                if action == 'DescribeServerCertificates':
                    names = ['*.stage.example.test', 'stage.example.test'] if params['ServerCertificateId'] == 'slb-stage' else ['*.example.test', 'example.test']
                    return {'ServerCertificates': {'ServerCertificate': [{'ServerCertificateId': params['ServerCertificateId'],
                        'CommonName': names[0], 'SubjectAlternativeNames': {'SubjectAlternativeName': names}}]}}
                if action == 'DescribeInstance':
                    return {'InstanceId': 'waf-' + region}
                if action == 'DescribeDomains' and service == 'waf':
                    assert params['PageSize'] == 10
                    return {'Domains': []}
                if action == 'DescribeCloudResources':
                    return {'CloudResources': []}
                if action == 'DescribeCloudResourceAccessPortDetails':
                    rid = params['ResourceInstanceId']
                    return {'AccessPortDetails': [{'Port': 443, 'Protocol': 'https',
                        'CloudResourceId': rid + '-443-ecs', 'Certificates': [{'AppliedType': 'default', 'CertificateId': '11-cn-hangzhou'}]}]}
                if action == 'DescribeInstances':
                    rid = json.loads(params['InstanceIds'])[0]
                    return {'Instances': {'Instance': [{'InstanceId': rid,
                        'PublicIpAddress': {'IpAddress': ['203.0.113.2' if rid == 'i-cn' else '203.0.113.3']}}]}}
                raise AssertionError((service, action, params))
        return Api()

    def scan(self, products, regions=None):
        return discover_complex({}, products, regions or ['cn-shenzhen', 'cn-hongkong'],
            {'resources': self.resources, 'ecs_regions': {'i-cn': 'cn-shenzhen', 'i-hk': 'cn-hongkong'}}, api_factory=self.factory)


class CloudDiscoveryTests(unittest.TestCase):
    def test_inventory_pagination_preserves_wildcards_and_drops_sensitive_fields(self):
        first = [{'Id': i, 'CloudProduct': 'ECS', 'InstanceId': f'i-{i}', 'RegionId': 'cn-shenzhen'} for i in range(100)]
        second = [{'Id': 101, 'CloudProduct': 'WAF', 'CertId': 11, 'UseSsl': 1,
            'Domain': '*.example.test', 'InstanceId': 'i-1', 'Key': 'PRIVATE-SENTINEL', 'Secret': 'SECRET-SENTINEL'}]
        class Api:
            def rpc(self, service, action, **params):
                return {'Total': 101, 'Data': first if params['CurrentPage'] == 1 else second}
        inventory = read_inventory(Api())
        self.assertEqual(inventory['resources'][0]['Domain'], '*.example.test')
        self.assertEqual(len(inventory['resources']), 1)
        self.assertEqual(inventory['ecs_regions']['i-1'], 'cn-shenzhen')
        self.assertNotIn('SENTINEL', json.dumps(inventory))

    def test_ga_https_discovered_from_dns_and_tcp_passthrough_is_skipped(self):
        found, errors = FakeCloud().scan(['ga'])
        self.assertEqual(errors, [])
        self.assertEqual(len(found), 1)
        row = found[0]
        self.assertEqual(row['domain'], 'atrust.example.test')
        self.assertEqual(row['config']['cloud_domain'], '*.example.test')
        self.assertEqual(row['config']['listener_id'], 'lsr-1')
        self.assertEqual(row['config']['required_domains'], ['*.example.test', 'example.test'])
        self.assertTrue(row['enabled'])

    def test_clb_default_and_wildcard_extension_are_distinct_certificate_slots(self):
        found, errors = FakeCloud().scan(['clb'], ['cn-shenzhen'])
        self.assertEqual(errors, [])
        self.assertEqual(len(found), 2)
        default = next(t for t in found if not t['config'].get('domain_extension_id'))
        extension = next(t for t in found if t['config'].get('domain_extension_id'))
        self.assertEqual(default['domain'], 'api.example.test')
        self.assertEqual(extension['domain'], 'foo.stage.example.test')
        self.assertEqual(extension['config']['cloud_domain'], '*.stage.example.test')
        self.assertNotEqual(default['resource_key'], extension['resource_key'])
        self.assertTrue(default['enabled'] and extension['enabled'])

    def test_waf_cloud_ecs_seeds_include_mainland_and_hong_kong_control_planes(self):
        cloud = FakeCloud()
        found, errors = cloud.scan(['waf'])
        self.assertEqual(errors, [])
        self.assertEqual(len(found), 2)
        self.assertEqual({t['region'] for t in found}, {'cn-hangzhou', 'ap-southeast-1'})
        self.assertEqual({t['domain'] for t in found}, {'wafcn.example.test', 'wafhk.example.test'})
        for target in found:
            self.assertEqual(target['kind'], 'waf_cloud')
            self.assertEqual(target['config']['resource_product'], 'ecs')
            self.assertTrue(target['config']['cloud_resource_id'].endswith('-443-ecs'))
        self.assertFalse(any(region == 'cn-hongkong' for region, service, _, _ in cloud.calls if service == 'waf'))

    def test_missing_dns_keeps_wildcard_resource_visible_but_disabled(self):
        cloud = FakeCloud()
        with patch('app.cloud_discovery.read_dns', return_value=[]):
            found, errors = cloud.scan(['ga'])
        self.assertEqual(errors, [])
        self.assertEqual(found[0]['domain'], '*.example.test')
        self.assertFalse(found[0]['enabled'])
        self.assertTrue(found[0]['observed']['configuration_required'])

    def test_probe_mapping_handles_cname_cycles_without_using_unrelated_names(self):
        records = [('one.example.test', 'two.example.test'), ('two.example.test', 'one.example.test'),
                   ('valid.example.test', 'ga.provider.example'), ('evil.example.net', 'ga.provider.example')]
        self.assertEqual(probe_name(['*.example.test'], ['ga.provider.example'], records), 'valid.example.test')

    def test_narrow_certificate_cannot_replace_shared_listener_wildcard(self):
        version = SimpleNamespace(key_encrypted='ciphertext', not_before=now() - timedelta(days=1),
                                  not_after=now() + timedelta(days=30), domains=['api.example.test'])
        target = SimpleNamespace(domain='api.example.test', config={'required_domains': ['*.example.test']})
        with self.assertRaisesRegex(SafeError, '没有覆盖'):
            validate_target_deploy(version, target)
        target.domain = '*.example.test'
        with self.assertRaisesRegex(SafeError, '具体业务域名'):
            validate_target_deploy(version, target)

    def test_cas_certificate_filter_is_json_not_repeated_rpc_parameters(self):
        api = Aliyun({'access_key_id': 'fake', 'access_key_secret': 'fake'})
        with patch.object(api.client, 'do_action_with_exception', return_value=b'{"Data":[]}') as request:
            api.rpc('cas', 'ListCloudResources', CertIds=[11, 22])
        params = request.call_args.args[0].get_query_params()
        self.assertEqual(json.loads(params['CertIds']), [11, 22])
        self.assertNotIn('CertIds.1', params)

    def test_waf_replacement_selects_cloud_port_and_preserves_other_certificates(self):
        api = Aliyun({'access_key_id': 'fake', 'access_key_secret': 'fake'})
        target = SimpleNamespace(kind='waf_cloud', region='cn-hangzhou', domain='api.example.test', config={
            'instance_id': 'waf', 'resource_instance_id': 'host', 'resource_product': 'ecs', 'port': 443,
            'cloud_resource_id': 'correct-port', 'replace_certificate_id': '11-cn-hangzhou'})
        captured = {}
        def rpc(service, action, **params):
            if action == 'DescribeCloudResourceAccessPortDetails':
                return {'AccessPortDetails': [
                    {'Port': 443, 'Protocol': 'https', 'CloudResourceId': 'other-port', 'Certificates': []},
                    {'Port': 443, 'Protocol': 'https', 'CloudResourceId': 'correct-port', 'Certificates': [
                        {'CertificateId': '11', 'AppliedType': 'default'}, {'CertificateId': '22', 'AppliedType': 'extension'}]}]}
            captured.update(params)
            return {'RequestId': 'fixture'}
        with patch.object(api, 'rpc', side_effect=rpc):
            api.apply_target(target, 'cert', 'key', 'fingerprint', {'cas_cert_id': '99', 'job_id': 'fixture'}, lambda **kw: None)
        self.assertEqual(captured['CloudResourceId'], 'correct-port')
        self.assertEqual(captured['Certificates'], [{'CertificateId': '99-cn-hangzhou', 'AppliedType': 'default'},
                                                   {'CertificateId': '22', 'AppliedType': 'extension'}])


class CloudInventoryApiTests(base.BaseTest):
    login = base.ApiTests.login
    def setUp(self):
        super().setUp()
        self.client = TestClient(base.app, base_url='http://127.0.0.1:18090')
        self.client.__enter__(); self.client.headers['origin'] = 'http://127.0.0.1:18090'; self.login()

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def test_cached_inventory_is_private_field_filtered_and_deleted_credentials_are_hidden(self):
        with Session() as db:
            credential = Credential(name='cloud', kind='aliyun', encrypted=seal({}))
            db.add(credential); db.flush(); identity = credential.id
            set_setting(db, 'cloud_inventory:' + identity, {'synced_at': now().isoformat(), 'resources': [
                {'Id': 1, 'CloudProduct': 'WAF', 'CertId': 11, 'Domain': '*.example.test', 'Key': 'PRIVATE-SENTINEL'}]})
            db.commit()
        response = self.client.get('/api/cloud-resources')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['resources']), 1)
        self.assertNotIn('SENTINEL', response.text)
        self.assertEqual(self.client.delete('/api/credentials/' + identity).status_code, 200)
        self.assertEqual(self.client.get('/api/cloud-resources').json()['resources'], [])
        self.client.cookies.clear()
        self.assertEqual(self.client.get('/api/cloud-resources').status_code, 401)

    def test_concurrent_discovery_requests_do_not_coalesce_different_products(self):
        with Session() as db:
            c = Credential(name='cloud', kind='aliyun', encrypted=seal({}))
            db.add(c); db.flush()
            first = enqueue(db, 'discover', args={'credential_id': c.id, 'products': ['oss'], 'regions': ['cn-shenzhen']})
            second = enqueue(db, 'discover', args={'credential_id': c.id, 'products': ['ga'], 'regions': ['cn-shenzhen']})
            again = enqueue(db, 'discover', args={'credential_id': c.id, 'products': ['oss'], 'regions': ['cn-shenzhen']})
            self.assertNotEqual(first.id, second.id)
            self.assertEqual(first.id, again.id)

    def test_binding_narrow_certificate_to_shared_cloud_scope_is_rejected(self):
        with Session() as db:
            c = Credential(name='cloud', kind='aliyun', encrypted=seal({}))
            cert = Certificate(name='single name'); db.add_all([c, cert]); db.flush()
            add_version(db, cert, *base.bundle()); db.commit(); cid, certid = c.id, cert.id
        response = self.client.post('/api/targets', json={'name': 'GA shared', 'kind': 'ga', 'domain': 'api.example.test',
            'credential_id': cid, 'certificate_id': certid, 'config': {'listener_id': 'lsr', 'required_domains': ['*.example.test']}})
        self.assertEqual(response.status_code, 400)
        self.assertIn('全部证书范围', response.text)
