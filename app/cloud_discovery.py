"""Discover certificate slots, preserving their scope and authoritative resource identity."""
import json
from .cloud import Aliyun
from .certificates import covers, domain_name
from .security import SafeError, clean_error

PRODUCTS = {'DCDN': 'dcdn', 'FC': 'fc', 'GA': 'ga', 'OSS': 'oss', 'SLB': 'clb', 'WAF': 'waf'}
RESOURCE_FIELDS = ('Id', 'CloudProduct', 'CertId', 'CertName', 'CertEndTime', 'Domain', 'InstanceId',
                   'ListenerId', 'ListenerPort', 'DefaultResource', 'EnableHttps', 'UseSsl',
                   'RegionId', 'Status', 'GmtModified')


def read_inventory(api, include_certificates=False):
    resources, ecs_regions, seen = [], {}, set()
    for page in range(1, 101):
        result = api.rpc('cas', 'ListCloudResources', CloudName='aliyun', CurrentPage=page, ShowSize=100)
        rows = result.get('Data', [])
        for row in rows:
            if row.get('CloudProduct') == 'ECS' and row.get('InstanceId') and row.get('RegionId'):
                ecs_regions[row['InstanceId']] = row['RegionId']
            identity = str(row.get('Id', ''))
            if (identity and identity not in seen and row.get('CloudProduct') in PRODUCTS
                    and str(row.get('CertId') or '0') != '0' and row.get('UseSsl') in (1, True, '1')):
                resources.append({key: row.get(key) for key in RESOURCE_FIELDS})
                seen.add(identity)
        if len(rows) < 100 or page * 100 >= int(result.get('Total') or 0):
            inventory = {'resources': resources, 'ecs_regions': ecs_regions}
            if include_certificates:
                metadata = {}
                certificate_index(api, metadata)
                inventory['certificates'] = metadata
            return inventory
    raise SafeError('证书部署清单超过扫描上限，请缩小账号资源范围')


def scopes(values):
    result = []
    for value in values:
        try:
            value = domain_name(value)
            if value not in result:
                result.append(value)
        except (SafeError, AttributeError):
            continue
    return result


def cert_id(value):
    return str(value or '').split('-cn-', 1)[0].split('-ap-', 1)[0]


def certificate_index(api, metadata=None):
    result = {}
    for page in range(1, 101):
        response = api.cas_certificates(page)
        rows = response.get('CertificateList', [])
        for row in rows:
            identity = cert_id(row.get('CertificateId'))
            result[identity] = scopes(str(row.get('Domain') or '').split(','))
            if metadata is not None:
                metadata[identity] = {'id': identity, 'name': row.get('CertificateName'),
                    'fingerprint': row.get('FingerPrint') or row.get('Fingerprint'),
                    'domains': result[identity], 'not_after': row.get('NotAfter')}
        if len(rows) < 100:
            return result
    raise SafeError('证书清单超过扫描上限')


def read_dns(api, wanted):
    zones, records = [], []
    for page in range(1, 101):
        response = api.rpc('alidns', 'DescribeDomains', PageNumber=page, PageSize=100)
        rows = response.get('Domains', {}).get('Domain', [])
        for row in rows:
            zone = row.get('DomainName', '')
            if any(d.removeprefix('*.') == zone or d.endswith('.' + zone) for d in wanted):
                zones.append(zone)
        if len(rows) < 100:
            break
    for zone in zones:
        for page in range(1, 101):
            response = api.rpc('alidns', 'DescribeDomainRecords', DomainName=zone, PageNumber=page, PageSize=100)
            rows = response.get('DomainRecords', {}).get('Record', [])
            for row in rows:
                if row.get('Type') not in ('A', 'AAAA', 'CNAME') or row.get('Status', 'ENABLE') != 'ENABLE':
                    continue
                rr = row.get('RR', '@')
                name = zone if rr == '@' else rr + '.' + zone
                if '*' not in name:
                    try:
                        name = domain_name(name)
                    except SafeError:
                        continue
                    records.append((name, str(row.get('Value', '')).lower().rstrip('.')))
            if len(rows) < 100:
                break
    return records


def probe_name(required, destinations, records, explicit=''):
    if explicit and not explicit.startswith('*.') and covers(required, explicit):
        return explicit
    destinations = {str(v).lower().rstrip('.') for v in destinations if v}
    links = {}
    for name, value in records:
        links.setdefault(name, set()).add(value)
    def points(value, visited):
        if value in destinations:
            return True
        if value in visited or len(visited) >= 8:
            return False
        return any(points(v, visited | {value}) for v in links.get(value, ()))
    return next((name for name in sorted(links) if covers(required, name) and points(name, set())), '')


def slot(kind, scope, region, key, config, label, required, destinations, records, explicit=''):
    required = scopes(required or [scope])
    if not required:
        raise SafeError(f'{label} 没有可识别的证书域名范围')
    scope = scope or required[0]
    hostname = probe_name(required, destinations, records, explicit)
    config = {**config, 'cloud_domain': scope, 'required_domains': required}
    if destinations:
        config.setdefault('probe_address', next((v for v in destinations if v), ''))
    return dict(kind=kind, name=(label + ' · ' + scope)[:180], domain=hostname or scope,
                region=region, resource_key=key, config=config, enabled=bool(hostname),
                observed={} if hostname else {'configuration_required': True,
                    'configuration_note': '已发现证书关联，请配置具体业务域名用于 TLS 检查并启用目标'})


def discover_complex(secret, products, regions, inventory, api_factory=None):
    api_factory = api_factory or Aliyun
    resources = inventory.get('resources', [])
    found, errors = [], []
    central = api_factory(secret, 'cn-hangzhou')
    try:
        certificates = ({identity: row['domains'] for identity, row in inventory['certificates'].items()}
                        if 'certificates' in inventory else certificate_index(central))
    except SafeError as exc:
        certificates = {}
        errors.append('证书域名元数据：' + clean_error(exc))
    wanted = {d for names in certificates.values() for d in names}
    try:
        records = read_dns(central, wanted)
    except SafeError as exc:
        records = []
        errors.append('业务域名关联：' + clean_error(exc))
    def attempt(label, fn):
        try:
            fn()
        except SafeError as exc:
            errors.append(label + '：' + clean_error(exc))

    if 'ga' in products:
        def scan_ga():
            for page in range(1, 101):
                response = central.rpc('ga', 'ListAccelerators', RegionId='cn-hangzhou', PageNumber=page, PageSize=50)
                accelerators = response.get('Accelerators', [])
                for accelerator in accelerators:
                    aid = accelerator['AcceleratorId']
                    for lp in range(1, 101):
                        response = central.rpc('ga', 'ListListeners', RegionId='cn-hangzhou',
                                               AcceleratorId=aid, PageNumber=lp, PageSize=50)
                        listeners = response.get('Listeners', [])
                        for listener in listeners:
                            if listener.get('Protocol', '').lower() != 'https':
                                continue  # TCP pass-through terminates TLS on the backend.
                            lid = listener['ListenerId']
                            ports = listener.get('PortRanges', [])
                            port = int(ports[0]['FromPort']) if ports else 443
                            for index, cert in enumerate(listener.get('Certificates', [])):
                                required = certificates.get(cert_id(cert.get('Id')), [])
                                matching = next((r for r in resources if r.get('CloudProduct') == 'GA'
                                    and r.get('ListenerId') == lid and cert_id(r.get('CertId')) == cert_id(cert.get('Id'))), {})
                                scope = matching.get('Domain') or (required[0] if required else '')
                                if not scope:
                                    errors.append(f'GA {lid} 的证书域名尚未同步，请稍后重试')
                                    continue
                                role = 'default' if index == 0 else 'additional'
                                found.append(slot('ga', scope, 'cn-hangzhou', f'ga:{lid}:{role}:{scope}',
                                    {'listener_id': lid, 'accelerator_id': aid, 'certificate_role': role,
                                     'probe_port': port, 'cloud_certificate_id': cert.get('Id')},
                                    'GA ' + (accelerator.get('Name') or aid), required,
                                    [accelerator.get('DnsName', '')], records))
                        if len(listeners) < 50:
                            break
                if len(accelerators) < 50:
                    break
        attempt('GA', scan_ga)

    if 'clb' in products:
        for region in regions:
            def scan_clb(region=region):
                api = api_factory(secret, region)
                for page in range(1, 101):
                    response = api.rpc('slb', 'DescribeLoadBalancers', RegionId=region, PageNumber=page, PageSize=100)
                    lbs = response.get('LoadBalancers', {}).get('LoadBalancer', [])
                    for lb in lbs:
                        identity = lb['LoadBalancerId']
                        attrs = api.rpc('slb', 'DescribeLoadBalancerAttribute', RegionId=region, LoadBalancerId=identity)
                        for listener in attrs.get('ListenerPortsAndProtocol', {}).get('ListenerPortAndProtocol', []):
                            if listener.get('ListenerProtocol', '').lower() != 'https':
                                continue
                            port = int(listener['ListenerPort'])
                            detail = api.rpc('slb', 'DescribeLoadBalancerHTTPSListenerAttribute',
                                RegionId=region, LoadBalancerId=identity, ListenerPort=port)
                            slots = [(None, detail.get('ServerCertificateId'), '')] + [
                                (d.get('DomainExtensionId'), d.get('ServerCertificateId'), d.get('Domain', ''))
                                for d in detail.get('DomainExtensions', {}).get('DomainExtension', [])]
                            for extension, sid, domain in slots:
                                if not sid:
                                    continue
                                response = api.rpc('slb', 'DescribeServerCertificates', RegionId=region, ServerCertificateId=sid)
                                certs = response.get('ServerCertificates', {}).get('ServerCertificate', [])
                                cert = next((c for c in certs if c.get('ServerCertificateId') == sid), {})
                                required = scopes(cert.get('SubjectAlternativeNames', {}).get('SubjectAlternativeName', [])
                                                  or [cert.get('CommonName', '')])
                                scope = domain or (required[0] if required else '')
                                if not scope:
                                    errors.append(f'CLB {identity}:{port} 的证书域名无法识别')
                                    continue
                                config = {'load_balancer_id': identity, 'listener_port': port,
                                          'probe_port': port, 'cloud_certificate_id': sid}
                                if extension:
                                    config['domain_extension_id'] = extension
                                found.append(slot('clb', scope, region, f'clb:{identity}:{port}:{extension or "default"}',
                                    config, 'CLB ' + (lb.get('LoadBalancerName') or identity), required,
                                    [lb.get('Address', '')], records, explicit=domain))
                    if len(lbs) < 100:
                        break
            attempt('CLB ' + region, scan_clb)

    if 'waf' in products:
        controls = []
        if any(r.startswith('cn-') and r != 'cn-hongkong' for r in regions):
            controls.append('cn-hangzhou')
        if any(not r.startswith('cn-') or r == 'cn-hongkong' for r in regions):
            controls.append('ap-southeast-1')
        for region in controls:
            def scan_waf(region=region):
                api = api_factory(secret, region)
                result = api.rpc('waf', 'DescribeInstance', RegionId=region)
                instance = result.get('InstanceId') or result.get('InstanceInfo', {}).get('InstanceId')
                if not instance:
                    return
                # CNAME onboarding and cloud-product onboarding are separate inventories.
                for page in range(1, 101):
                    response = api.rpc('waf', 'DescribeDomains', RegionId=region, InstanceId=instance,
                                       PageNumber=page, PageSize=10)
                    domains = response.get('Domains', [])
                    for domain in domains:
                        scope = domain if isinstance(domain, str) else domain.get('Domain', '')
                        if not scope:
                            continue
                        required = [scope]
                        dest = [] if isinstance(domain, str) else [domain.get('Cname', '')]
                        found.append(slot('waf', scope, region, f'{instance}:{scope}',
                            {'instance_id': instance, 'api_version': '3.0', 'cloud_domain': scope},
                            'WAF CNAME', required, dest, records, explicit=scope))
                    if len(domains) < 10:
                        break
                seeds = {}
                for page in range(1, 101):
                    response = api.rpc('waf', 'DescribeCloudResources', RegionId=region, InstanceId=instance,
                                       PageNumber=page, PageSize=10)
                    rows = response.get('CloudResources', [])
                    for row in rows:
                        seeds[(row['ResourceInstanceId'], row['ResourceProduct'])] = row
                    if len(rows) < 10:
                        break
                # SSL's deployment list also includes transparent ECS and older cloud bindings.
                for resource in resources:
                    if resource.get('CloudProduct') != 'WAF' or resource.get('RegionId') != region:
                        continue
                    rid = resource.get('InstanceId', '')
                    product = 'ecs' if rid.startswith('i-') else 'clb7' if rid.startswith('lb-') else ''
                    if product:
                        seeds.setdefault((rid, product), {})
                for (rid, product), metadata in seeds.items():
                    def scan_ports(rid=rid, product=product, metadata=metadata):
                        ports = []
                        for page in range(1, 101):
                            response = api.rpc('waf', 'DescribeCloudResourceAccessPortDetails', RegionId=region,
                                InstanceId=instance, ResourceInstanceId=rid, ResourceProduct=product,
                                PageNumber=page, PageSize=10)
                            items = response.get('AccessPortDetails', [])
                            ports.extend(items)
                            if len(items) < 10:
                                break
                        addresses = [metadata.get('ResourceInstanceIp', '')]
                        if product == 'ecs' and inventory.get('ecs_regions', {}).get(rid):
                            er = inventory['ecs_regions'][rid]
                            response = api_factory(secret, er).rpc('ecs', 'DescribeInstances',
                                RegionId=er, InstanceIds=json.dumps([rid]))
                            for ecs in response.get('Instances', {}).get('Instance', []):
                                addresses += ecs.get('PublicIpAddress', {}).get('IpAddress', [])
                                addresses.append(ecs.get('EipAddress', {}).get('IpAddress', ''))
                        addresses = [a for a in addresses if a]
                        for port in ports:
                            if port.get('Protocol', '').lower() != 'https':
                                continue
                            for cert in port.get('Certificates', []):
                                cid = cert.get('CertificateId')
                                required = certificates.get(cert_id(cid), [])
                                resource = next((r for r in resources if r.get('CloudProduct') == 'WAF'
                                    and r.get('InstanceId') == rid and cert_id(r.get('CertId')) == cert_id(cid)), {})
                                scope = resource.get('Domain') or (required[0] if required else '')
                                if not scope:
                                    errors.append(f'WAF {rid} 证书 {cid} 的域名无法识别')
                                    continue
                                crid = port['CloudResourceId']
                                role = cert.get('AppliedType', 'default')
                                config = {'instance_id': instance, 'resource_instance_id': rid,
                                    'resource_product': product, 'cloud_resource_id': crid,
                                    'port': int(port['Port']), 'replace_certificate_id': cid,
                                    'probe_port': int(port['Port'])}
                                explicit = metadata.get('ResourceDomain', '')
                                found.append(slot('waf_cloud', scope, region, f'waf:{instance}:{crid}:{role}:{scope}',
                                    config, 'WAF ' + rid, required, addresses, records, explicit=explicit))
                    attempt('WAF 接入资源 ' + rid, scan_ports)
            attempt('WAF ' + region, scan_waf)
    return found, errors
