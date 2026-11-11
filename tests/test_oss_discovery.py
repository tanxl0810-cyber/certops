import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from xml.etree import ElementTree as ET

import oss2
from app.cloud import discover


class OssDiscoveryTests(unittest.TestCase):
    secret = {'access_key_id': 'fixture-id', 'access_key_secret': 'fixture-secret'}

    @staticmethod
    def metadata(name='example-bucket', location='oss-cn-shenzhen', region='cn-shenzhen'):
        # Exercise the installed SDK's real XML parser, including legacy responses.
        root = ET.Element('ListAllMyBucketsResult')
        bucket = ET.SubElement(ET.SubElement(root, 'Buckets'), 'Bucket')
        for key, value in {'Name': name, 'Location': location, 'CreationDate': '2026-01-01T00:00:00.000Z',
                           'ExtranetEndpoint': location + '.aliyuncs.com',
                           'IntranetEndpoint': location + '-internal.aliyuncs.com',
                           'StorageClass': 'Standard', 'Region': region}.items():
            if value is not None:
                ET.SubElement(bucket, key).text = value
        result = SimpleNamespace(buckets=[])
        oss2.xml_utils.parse_list_buckets(result, ET.tostring(root))
        return result.buckets[0]

    def scan(self, buckets, regions=None, client=None, secret=None, iterator_error=None):
        cname = SimpleNamespace(domain='example-bucket.example.test')
        client = client or Mock(list_bucket_cname=Mock(return_value=SimpleNamespace(cname=[cname])))
        with patch('app.cloud.Aliyun'), patch('oss2.Service'), \
             patch('oss2.BucketIterator', return_value=buckets, side_effect=iterator_error), \
             patch('oss2.Bucket', side_effect=lambda *a, **kw: client) as bucket:
            found, errors = discover(secret or self.secret, ['oss'], regions or ['cn-shenzhen'])
        return found, errors, bucket

    def test_sdk_region_and_oss_location_are_not_compared_as_identical_ids(self):
        metadata = self.metadata()
        self.assertEqual((metadata.location, metadata.region), ('oss-cn-shenzhen', 'cn-shenzhen'))
        found, errors, bucket = self.scan([metadata])
        self.assertEqual(errors, [])
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]['region'], found[0]['domain'], found[0]['resource_key']),
                         ('cn-shenzhen', 'example-bucket.example.test', 'example-bucket:example-bucket.example.test'))
        self.assertEqual(found[0]['config'], {'bucket': 'example-bucket'})
        self.assertNotIn('certificate_id', found[0])
        self.assertEqual(bucket.call_args.args[1:3], ('https://oss-cn-shenzhen.aliyuncs.com', 'example-bucket'))

    def test_legacy_location_fallback_with_missing_region_field(self):
        for missing_attribute in (False, True):
            with self.subTest(missing_attribute=missing_attribute):
                info = self.metadata(region=None)
                if missing_attribute:
                    del info.region
                found, errors, bucket = self.scan([info])
                self.assertEqual(errors, [])
                self.assertEqual(found[0]['region'], 'cn-shenzhen')
                self.assertEqual(bucket.call_args.args[1], 'https://oss-cn-shenzhen.aliyuncs.com')

    def test_unselected_regions_are_skipped_and_hong_kong_endpoint_is_correct(self):
        buckets = [self.metadata(), self.metadata('hk-bucket', 'oss-cn-hongkong', 'cn-hongkong')]
        found, errors, bucket = self.scan(buckets, ['cn-hongkong'])
        self.assertEqual(errors, [])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['region'], 'cn-hongkong')
        self.assertEqual(found[0]['config']['bucket'], 'hk-bucket')
        self.assertEqual(bucket.call_args.args[1], 'https://oss-cn-hongkong.aliyuncs.com')
        self.assertEqual(bucket.call_count, 1)

    def test_failed_bucket_does_not_hide_subsequent_buckets_or_leak_request_details(self):
        denied = RuntimeError('Authorization: do-not-log-this-sensitive-request')
        denied.code, denied.request_id = 'AccessDenied', 'fixture-request-id'
        failed = Mock(list_bucket_cname=Mock(side_effect=denied))
        good = Mock(list_bucket_cname=Mock(return_value=SimpleNamespace(cname=[
            SimpleNamespace(domain='example-bucket.example.test')])))
        with patch('app.cloud.Aliyun'), patch('oss2.Service'), \
             patch('oss2.BucketIterator', return_value=[self.metadata('denied-bucket'), self.metadata()]), \
             patch('oss2.Bucket', side_effect=[failed, good]):
            found, errors = discover(self.secret, ['oss'], ['cn-shenzhen'])
        self.assertEqual(len(found), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn('denied-bucket (cn-shenzhen)', errors[0])
        self.assertIn('AccessDenied', errors[0])
        self.assertIn('oss:ListCname', errors[0])
        self.assertIn('fixture-request-id', errors[0])
        self.assertNotIn('do-not-log', errors[0])
        self.assertNotIn('GetBucketCname', errors[0])

    def test_list_buckets_failure_reports_correct_api_and_permission(self):
        denied = RuntimeError('do-not-log-request-details')
        denied.code = 'AccessDenied'
        found, errors, bucket = self.scan([], iterator_error=denied)
        self.assertEqual(found, [])
        self.assertIn('OSS ListBuckets: AccessDenied', errors[0])
        self.assertIn('oss:ListBuckets', errors[0])
        self.assertNotIn('do-not-log', errors[0])
        bucket.assert_not_called()

    def test_bucket_with_no_custom_domains_is_a_normal_empty_result(self):
        found, errors, _ = self.scan([self.metadata()], client=Mock(
            list_bucket_cname=Mock(return_value=SimpleNamespace(cname=[]))))
        self.assertEqual((found, errors), ([], []))

    def test_temporary_credentials_remain_supported(self):
        with patch('oss2.StsAuth') as auth:
            found, errors, _ = self.scan([self.metadata()], secret={**self.secret, 'security_token': 'fixture-sts'})
        auth.assert_called_once_with('fixture-id', 'fixture-secret', 'fixture-sts')
        self.assertEqual(len(found), 1)
        self.assertEqual(errors, [])
