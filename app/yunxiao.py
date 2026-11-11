"""Yunxiao Central edition OpenAPI. Tokens never enter URLs or returned errors."""
import json
import hashlib
import re

import httpx

from .security import SafeError


class SubmissionUnknown(SafeError):
    pass


class Yunxiao:
    def __init__(self, secret, transport=None):
        self.token = secret.get('token', '')
        organization = secret.get('organization_id', '')
        if not self.token or not re.fullmatch(r'[A-Za-z0-9_-]{8,80}', organization):
            raise SafeError('请填写云效个人访问令牌和组织 ID')
        self.base = 'https://openapi-rdc.aliyuncs.com/oapi/v1/flow/organizations/' + organization
        self.transport = transport

    @staticmethod
    def identifier(value):
        value = str(value)
        if not re.fullmatch(r'[1-9][0-9]{0,19}', value):
            raise SafeError('云效流水线或运行编号不正确')
        return value

    def request(self, method, path, body=None, params=None):
        uncertain = method == 'POST'
        try:
            with httpx.Client(timeout=httpx.Timeout(25, connect=8), trust_env=False,
                              follow_redirects=False, transport=self.transport) as client:
                response = client.request(method, self.base + path, json=body, params=params,
                    headers={'x-yunxiao-token': self.token, 'Content-Type': 'application/json'})
        except httpx.HTTPError:
            error = SubmissionUnknown if uncertain else SafeError
            raise error('云效 API 连接失败；触发结果不明时不会重复提交') from None
        if (response.status_code >= 500 or response.status_code == 408) and uncertain:
            raise SubmissionUnknown('云效触发响应异常，正在核对运行实例')
        if not 200 <= response.status_code < 300:
            raise SafeError(f'云效 API 返回 HTTP {response.status_code}，请检查令牌权限、组织及流水线配置')
        try:
            result = response.json()
        except ValueError:
            error = SubmissionUnknown if uncertain else SafeError
            raise error('云效 API 返回格式不正确') from None
        if isinstance(result, dict):
            if result.get('success') is False or result.get('successful') is False:
                raise SafeError('云效 API 拒绝请求，请核对权限及流水线配置')
            if isinstance(result.get('result'), (dict, list)):
                result = result['result']
        return result

    def pipeline(self, pipeline_id):
        return self.request('GET', '/pipelines/' + self.identifier(pipeline_id))

    def configuration_hash(self, pipeline_id):
        detail = self.pipeline(pipeline_id)
        content = (detail.get('content') or detail.get('pipelineConfig', {}).get('flow', '')) if isinstance(detail, dict) else ''
        if not content or '/usr/local/libexec/certops-pipeline.py' not in content:
            raise SafeError('流水线尚未配置证书专用执行脚本，请先核对流程配置')
        canonical = content.replace('\r\n', '\n').strip() + '\n'
        return hashlib.sha256(canonical.encode()).hexdigest()

    def start(self, pipeline_id, variables):
        result = self.request('POST', '/pipelines/' + self.identifier(pipeline_id) + '/runs',
            {'params': json.dumps({'envs': variables, 'comment': 'CertOps ' + variables['CERTOPS_JOB_ID']})})
        run_id = result.get('pipelineRunId', result.get('id')) if isinstance(result, dict) else result
        if not run_id or not str(run_id).isdigit():
            raise SubmissionUnknown('云效未返回可识别的运行编号，正在核对运行实例')
        return self.identifier(run_id)

    def run(self, pipeline_id, run_id):
        return self.request('GET', '/pipelines/' + self.identifier(pipeline_id) + '/runs/' + self.identifier(run_id))

    def find_run(self, pipeline_id, job_id, attempt_id, since):
        result = self.request('GET', '/pipelines/' + self.identifier(pipeline_id) + '/runs',
                              params={'perPage': 10, 'page': 1, 'startTime': int(since.timestamp() * 1000) - 1000})
        rows = result if isinstance(result, list) else next((result[k] for k in ('items', 'data', 'list', 'pipelineRuns')
                if isinstance(result, dict) and isinstance(result.get(k), list)), [])
        for item in rows[:10]:
            run_id = item.get('pipelineRunId', item.get('id'))
            if not run_id:
                continue
            detail = self.run(pipeline_id, run_id)
            variables = {str(p.get('key')): str(p.get('value')) for p in detail.get('globalParams', [])}
            if variables.get('CERTOPS_JOB_ID') == job_id and variables.get('CERTOPS_ATTEMPT_ID') == attempt_id:
                return self.identifier(run_id)
        return None
