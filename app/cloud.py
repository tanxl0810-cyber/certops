"""Alibaba Cloud adapters. API responses containing private keys never enter job logs."""
import json
import time
from urllib.parse import quote
from xml.etree import ElementTree as ET
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
from aliyunsdkcore.acs_exception.exceptions import ServerException
from .security import SafeError, clean_error

SERVICES = {
    'cas': ('cas.aliyuncs.com', '2020-04-07'),
    'dcdn': ('dcdn.aliyuncs.com', '2018-01-15'),
    'ga': ('ga.cn-hangzhou.aliyuncs.com', '2019-11-20'),
    'slb': (None, '2014-05-15'),
    'waf': (None, '2021-10-01'),
    'alidns': ('alidns.aliyuncs.com', '2015-01-09'),
    'ecs': (None, '2014-05-26'),
}


def flatten(params, prefix=''):
    result = {}
    for key, value in params.items():
        if value is None:
            continue
        name = f'{prefix}.{key}' if prefix else key
        if isinstance(value, dict):
            result.update(flatten(value, name))
        elif isinstance(value, list):
            for index, item in enumerate(value, 1):
                if isinstance(item, dict):
                    result.update(flatten(item, f'{name}.{index}'))
                else:
                    result[f'{name}.{index}'] = str(item)
        else:
            result[name] = str(value).lower() if isinstance(value, bool) else str(value)
    return result


class Aliyun:
    def __init__(self, secret, region='cn-hangzhou'):
        if not secret.get('access_key_id') or not secret.get('access_key_secret'):
            raise SafeError('请先配置阿里云 AccessKey')
        self.secret, self.region = secret, region
        self.client = AcsClient(secret['access_key_id'], secret['access_key_secret'], region,
                                auto_retry=False, connect_timeout=10, timeout=35)

    def rpc(self, service, action, _version=None, **params):
        endpoint, version = SERVICES[service]
        if service == 'slb':
            endpoint = f'slb.{self.region}.aliyuncs.com'
        elif service == 'waf':
            endpoint = ('wafopenapi.cn-hangzhou.aliyuncs.com' if self.region.startswith('cn-')
                        else 'wafopenapi.ap-southeast-1.aliyuncs.com')
        elif service == 'ecs':
            endpoint = f'ecs.{self.region}.aliyuncs.com'
        req = CommonRequest()
        req.set_domain(endpoint)
        req.set_version(_version or version)
        req.set_action_name(action)
        req.set_protocol_type('https')
        req.set_method('POST')
        req.set_accept_format('json')
        if self.secret.get('security_token'):
            params['SecurityToken'] = self.secret['security_token']
        if service == 'cas' and action == 'ListCloudResources' and isinstance(params.get('CertIds'), list):
            params['CertIds'] = json.dumps(params['CertIds'])
        for key, value in flatten(params).items():
            req.add_query_param(key, value)
        try:
            return json.loads(self.client.do_action_with_exception(req))
        except ServerException as exc:
            raise SafeError(f'{action}: {exc.get_error_code()} — {clean_error(exc.get_error_msg())}') from None
        except SafeError:
            raise
        except Exception:
            raise SafeError(f'{action}: 云 API 连接失败或超时；请核对网络、地域和授权，写入操作需先核对云端结果') from None

    def fc(self, method, domain='', body=None, api_version='2023-03-30', next_token=None):
        from alibabacloud_tea_openapi.client import Client as GenericClient
        from alibabacloud_fc20230330.client import Client as FCClient
        from alibabacloud_tea_openapi import utils_models as models
        from darabonba.runtime import RuntimeOptions
        config = models.Config(access_key_id=self.secret['access_key_id'],
            access_key_secret=self.secret['access_key_secret'], security_token=self.secret.get('security_token'),
            region_id=self.region,
            connect_timeout=10000, read_timeout=30000)
        if api_version != '2023-03-30':
            account = self.secret.get('account_id', '')
            if not account:
                raise SafeError('FC 2.0 需要在阿里云凭据中填写账号 UID')
            config.endpoint = f'{account}.{self.region}.fc.aliyuncs.com'
        client = FCClient(config) if api_version == '2023-03-30' else GenericClient(config)
        action = {'GET': 'GetCustomDomain', 'PUT': 'UpdateCustomDomain'}[method] if domain else 'ListCustomDomains'
        params = models.Params(action=action, version=api_version, protocol='HTTPS',
            pathname=f'/{api_version}/custom-domains' + ('/' + quote(domain, safe='') if domain else ''),
            method=method, auth_type='AK', style='ROA', req_body_type='json', body_type='json')
        query = {'limit': '100'} if not domain else {}
        if next_token:
            query['nextToken'] = next_token
        req = models.OpenApiRequest(body=body, query=query)
        try:
            response = client.call_api(params, req, RuntimeOptions(autoretry=False))
            return response.get('body', {})
        except Exception as exc:
            code = getattr(exc, 'code', None) or 'RequestFailed'
            raise SafeError(f'FC {action}: {code}；请核对 FC 版本、地域和授权') from None

    def upload_cas(self, cert, key, name):
        result = self.rpc('cas', 'UploadUserCertificate', Name=name[:100], Cert=cert, Key=key)
        cert_id = result.get('CertId') or result.get('CertificateId')
        if not cert_id:
            raise SafeError('上传证书后未返回 CertId')
        return str(cert_id)

    def cas_instances(self, page=1):
        return self.rpc('cas', 'ListInstances', CurrentPage=page, ShowSize=100)

    def cas_certificates(self, page=1):
        return self.rpc('cas', 'ListCertificates', CurrentPage=page, ShowSize=100)

    def cas_download(self, cert_id):
        result = self.rpc('cas', 'GetUserCertificateDetail', CertId=int(cert_id), CertFilter=False)
        if not result.get('Cert'):
            raise SafeError('云端未返回 PEM 证书；当前仅支持标准 RSA/ECC 服务器证书')
        return result['Cert'], result.get('Key', '')

    def put_dns_validation(self, fqdn, record_type, value):
        """Only add an exact validation record; never overwrite unrelated TXT/CNAME values."""
        fqdn = fqdn.rstrip('.')
        for cut in range(1, len(fqdn.split('.'))):
            zone = '.'.join(fqdn.split('.')[cut:])
            try:
                self.rpc('alidns', 'DescribeDomainInfo', DomainName=zone)
                break
            except SafeError as exc:
                if 'InvalidDomainName' not in str(exc) and 'DomainRecordNotBelong' not in str(exc) and 'DomainNotFound' not in str(exc):
                    raise
        else:
            raise SafeError('未找到域名对应的阿里云 DNS 区域，请手动完成域名验证')
        rr = fqdn[:-(len(zone) + 1)] or '@'
        records = self.rpc('alidns', 'DescribeDomainRecords', DomainName=zone,
                           RRKeyWord=rr, SearchMode='EXACT', PageSize=500)
        existing = records.get('DomainRecords', {}).get('Record', [])
        for item in existing:
            if item.get('RR') == rr and item.get('Type') == record_type and item.get('Value', '').rstrip('.') == value.rstrip('.'):
                return {'record_id': item['RecordId'], 'created': False, 'fqdn': fqdn}
        if record_type == 'CNAME' and any(i.get('RR') == rr for i in existing):
            raise SafeError('验证 CNAME 与已有记录冲突，请人工核对；系统不会覆盖已有解析')
        result = self.rpc('alidns', 'AddDomainRecord', DomainName=zone, RR=rr, Type=record_type, Value=value, TTL=600)
        return {'record_id': result.get('RecordId'), 'created': True, 'fqdn': fqdn}

    def apply_target(self, target, cert_pem, key_pem, fingerprint, progress, persist):
        kind, config = target.kind, target.config
        region = target.region
        if kind == 'dcdn':
            return self.rpc('dcdn', 'SetDcdnDomainSSLCertificate', DomainName=target.domain,
                SSLProtocol='on', CertType='upload', CertName=f'certops-{fingerprint[:20]}',
                SSLPub=cert_pem, SSLPri=key_pem)
        if kind == 'fc':
            version = config.get('api_version', '2023-03-30')
            current = self.fc('GET', target.domain, api_version=version)
            body = {k: current[k] for k in ('protocol', 'routeConfig', 'authConfig', 'tlsConfig',
                'wafConfig') if k in current}
            body['certConfig'] = {'certName': f'certops-{fingerprint[:20]}',
                                  'certificate': cert_pem, 'privateKey': key_pem}
            if body.get('protocol') not in ('HTTPS', 'HTTP,HTTPS'):
                raise SafeError('FC 自定义域名尚未启用 HTTPS，请先完成首次 HTTPS 配置')
            return self.fc('PUT', target.domain, body, version)
        if kind in ('ga', 'waf', 'waf_cloud'):
            cert_id = progress.get('cas_cert_id')
            if not cert_id:
                cert_id = self.upload_cas(cert_pem, key_pem, f'certops-{fingerprint[:20]}')
                persist(cas_cert_id=cert_id)
            if kind == 'waf_cloud':
                from .cloud_discovery import cert_id as identity_key
                current = self.rpc('waf', 'DescribeCloudResourceAccessPortDetails',
                    RegionId=region, InstanceId=config['instance_id'],
                    ResourceInstanceId=config['resource_instance_id'], ResourceProduct=config['resource_product'],
                    Port=str(config['port']), Protocol='https', PageNumber=1, PageSize=10)
                ports = [p for p in current.get('AccessPortDetails', []) if
                         int(p.get('Port', 0)) == int(config['port']) and p.get('Protocol') == 'https'
                         and (not config.get('cloud_resource_id') or p.get('CloudResourceId') == config['cloud_resource_id'])]
                if len(ports) != 1:
                    raise SafeError('无法唯一定位 WAF 接入端口，请核对实例、产品类型和端口')
                port = ports[0]
                old_id = str(config['replace_certificate_id'])
                new_id = f'{cert_id}-cn-hangzhou' if '-cn-' in old_id else str(cert_id)
                existing = port.get('Certificates', [])
                if not existing:
                    raise SafeError('WAF 当前端口没有可替换的证书；请先完成首次 HTTPS 配置')
                if not any(identity_key(c.get('CertificateId')) == identity_key(old_id) for c in existing):
                    if any(identity_key(c.get('CertificateId')) == identity_key(new_id) for c in existing):
                        target.config = {**config, 'replace_certificate_id': new_id}
                        return {'RequestId': 'reconciled-existing-certificate'}
                    raise SafeError('指定旧证书 ID 与 WAF 当前绑定不一致，已停止更新以保留其他域名的证书')
                replacement = [{'CertificateId': new_id if identity_key(c['CertificateId']) == identity_key(old_id) else c['CertificateId'],
                                'AppliedType': c['AppliedType']} for c in existing]
                result = self.rpc('waf', 'ModifyCloudResourceCert', RegionId=region,
                    InstanceId=config['instance_id'], CloudResourceId=port['CloudResourceId'], Certificates=replacement)
                target.config = {**config, 'replace_certificate_id': new_id}
                return result
            if kind == 'ga':
                listener = config['listener_id']
                current = self.rpc('ga', 'DescribeListener', ListenerId=listener, RegionId='cn-hangzhou')
                if current.get('Protocol', '').lower() != 'https':
                    raise SafeError('GA 监听器不是 HTTPS；TCP 透传场景请更新后端服务器证书')
                if config.get('certificate_role', 'default') == 'additional':
                    return self.rpc('ga', 'UpdateAdditionalCertificateWithListener',
                        ListenerId=listener, AcceleratorId=config['accelerator_id'],
                        RegionId='cn-hangzhou', Domain=config.get('cloud_domain') or target.domain,
                        CertificateId=f'{cert_id}-cn-hangzhou', ClientToken=progress['job_id'])
                return self.rpc('ga', 'UpdateListener', ListenerId=listener,
                    RegionId='cn-hangzhou', ClientToken=progress['job_id'],
                    Certificates=[{'Id': f'{cert_id}-cn-hangzhou'}])
            version = config.get('api_version', '3.0')
            if version == '2.0':
                return self.rpc('waf', 'CreateCertificateByCertificateId', _version='2019-09-10',
                    InstanceId=config['instance_id'], Domain=config.get('cloud_domain') or target.domain, RegionId=region,
                    CertificateId=int(cert_id))
            return self.rpc('waf', 'ModifyDomainCert', InstanceId=config['instance_id'],
                Domain=config.get('cloud_domain') or target.domain, CertId=f'{cert_id}-cn-hangzhou', RegionId=region)
        if kind == 'clb':
            cert_id = progress.get('server_certificate_id')
            if not cert_id:
                result = self.rpc('slb', 'UploadServerCertificate', RegionId=region,
                    ServerCertificate=cert_pem, PrivateKey=key_pem,
                    ServerCertificateName=f'certops-{fingerprint[:20]}')
                cert_id = result['ServerCertificateId']
                persist(server_certificate_id=cert_id)
            if config.get('domain_extension_id'):
                return self.rpc('slb', 'SetDomainExtensionAttribute', RegionId=region,
                    DomainExtensionId=config['domain_extension_id'], ServerCertificateId=cert_id)
            return self.rpc('slb', 'SetLoadBalancerHTTPSListenerAttribute', RegionId=region,
                LoadBalancerId=config['load_balancer_id'], ListenerPort=int(config.get('listener_port', 443)),
                ServerCertificateId=cert_id)
        if kind == 'oss':
            import oss2
            auth = (oss2.StsAuth(self.secret['access_key_id'], self.secret['access_key_secret'], self.secret['security_token'])
                    if self.secret.get('security_token') else oss2.Auth(self.secret['access_key_id'], self.secret['access_key_secret']))
            bucket = oss2.Bucket(auth, f'https://oss-{region}.aliyuncs.com', config['bucket'], connect_timeout=15)
            root = ET.Element('BucketCnameConfiguration')
            node = ET.SubElement(root, 'Cname')
            ET.SubElement(node, 'Domain').text = target.domain
            cert = ET.SubElement(node, 'CertificateConfiguration')
            ET.SubElement(cert, 'Certificate').text = cert_pem
            ET.SubElement(cert, 'PrivateKey').text = key_pem
            if config.get('previous_cert_id'):
                ET.SubElement(cert, 'PreviousCertId').text = str(config['previous_cert_id'])
                ET.SubElement(cert, 'Force').text = 'false'
            else:
                ET.SubElement(cert, 'Force').text = 'true'
            try:
                result = bucket.put_bucket_cname(ET.tostring(root))
                return {'RequestId': result.request_id}
            except Exception as exc:
                raise SafeError(f'OSS PutCname: {getattr(exc, "code", "RequestFailed")}；请核对 Bucket、地域和域名绑定') from None
        raise SafeError('目标类型不支持云 API 部署')


def list_items(value, *names):
    if isinstance(value, list):
        return value
    for name in names:
        if isinstance(value, dict) and name in value:
            value = value[name]
    return value if isinstance(value, list) else []


def oss_discovery_error(action, exc, context=''):
    # SDK exception strings can contain request details. Log only diagnostic metadata.
    code = getattr(exc, 'code', None) or type(exc).__name__
    request_id = getattr(exc, 'request_id', '')
    reference = f'（RequestId: {request_id}）' if request_id else ''
    permission = 'oss:ListBuckets' if action == 'ListBuckets' else 'oss:ListCname'
    return clean_error(f'OSS {action}{context}: {code}{reference}；请核对网络、地域及 {permission} 权限')


def discover(secret, products, regions, inventory_snapshot=None):
    """Read-only discovery returns unbound targets; it never enables automatic deployment."""
    found, errors = [], []
    def add(kind, domain, region, key, config, name=None):
        if domain and not domain.startswith('*.'):
            found.append(dict(kind=kind, domain=domain, region=region,
                              resource_key=key, config=config, name=name or domain))
    if 'dcdn' in products:
        try:
            api = Aliyun(secret)
            for page in range(1, 101):
                result = api.rpc('dcdn', 'DescribeDcdnUserDomains', PageNumber=page, PageSize=50)
                rows = result.get('Domains', {}).get('PageData', [])
                for row in rows:
                    name = row['DomainName']
                    add('dcdn', name, 'cn-hangzhou', name, {})
                if len(rows) < 50:
                    break
        except SafeError as exc:
            errors.append(str(exc))
    for region in regions:
        api = Aliyun(secret, region)
        if 'fc' in products:
            try:
                token = None
                for _ in range(100):
                    result = api.fc('GET', next_token=token)
                    for row in result.get('customDomains', []):
                        name = row['domainName']
                        add('fc', name, region, f'{region}:{name}', {'api_version': '2023-03-30'})
                    token = result.get('nextToken')
                    if not token:
                        break
            except SafeError as exc:
                errors.append(str(exc))
    if 'oss' in products:
        try:
            import oss2
            auth = (oss2.StsAuth(secret['access_key_id'], secret['access_key_secret'], secret['security_token'])
                    if secret.get('security_token') else oss2.Auth(secret['access_key_id'], secret['access_key_secret']))
            service = oss2.Service(auth, 'https://oss-cn-hangzhou.aliyuncs.com', connect_timeout=10)
            for bucket_info in oss2.BucketIterator(service):
                # OSS Location is "oss-cn-shenzhen"; Region is "cn-shenzhen".
                # Older responses/SDKs can omit Region, so normalize Location as fallback.
                region = (getattr(bucket_info, 'region', None) or bucket_info.location or '').removeprefix('oss-')
                if region not in regions:
                    continue
                try:
                    bucket = oss2.Bucket(auth, f'https://oss-{region}.aliyuncs.com', bucket_info.name, connect_timeout=10)
                    for cname in bucket.list_bucket_cname().cname:
                        name = cname.domain
                        add('oss', name, region, f'{bucket_info.name}:{name}', {'bucket': bucket_info.name})
                except Exception as exc:
                    errors.append(oss_discovery_error('ListCname', exc, f' {bucket_info.name} ({region})'))
        except Exception as exc:
            errors.append(oss_discovery_error('ListBuckets', exc))
    if inventory_snapshot is not None or set(products) & {'ga', 'clb', 'waf'}:
        from .cloud_discovery import read_inventory, discover_complex
        inventory = {}
        try:
            inventory = read_inventory(Aliyun(secret), include_certificates=True)
            if inventory_snapshot is not None:
                inventory_snapshot.update(inventory)
        except SafeError as exc:
            errors.append('云端证书关联清单：' + clean_error(exc))
        if set(products) & {'ga', 'clb', 'waf'}:
            targets, warnings = discover_complex(secret, products, regions, inventory)
            found.extend(targets)
            errors.extend(warnings)
    return found, errors
