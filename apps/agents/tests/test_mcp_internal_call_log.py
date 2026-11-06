"""Internal MCP call log ingest (signed assertions, strict path and body rules)."""

from __future__ import annotations

import json
import time
import uuid

import jwt
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from shellui_django.mcp.internal import CALL_LOG_AUDIENCE, CALL_LOG_SCOPE, build_mcp_call_log_assertion

from apps.authapi.jwks import build_jwks_document, generate_rsa_key_pair, load_signing_key
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.federation.models import ProvisionedCompany, UpstreamAccount
from apps.agents.models import Agent, McpApprovalRequest
from apps.agents.tests.mcp_test_settings import (
    TEST_CALLER_SIGNING,
    TRUSTED_TEST_CALLER_SETTINGS,
    approval_authority_snapshot_for_agent,
)

User = get_user_model()

_PATH = '/api/v1/mcp/internal/mcp-call-logs'


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    STORAGE_SERVICE_URL='https://storage.region.example',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpInternalCallLogTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company = __import__('apps.companies.models', fromlist=['Company']).Company.objects.create(
            name='LogCo', slug='log-co'
        )
        self.user = User.objects.create_user(username='u1', email='u@log.co', password='unused')
        self.company.owners.add(self.user)
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            created_by=self.user,
            services_allowed=['storage'],
        )

    def _assertion(self):
        return build_mcp_call_log_assertion(
            audience_url='https://identity.test',
            private_key_pem=TEST_CALLER_SIGNING['private_key_pem'],
            kid=TEST_CALLER_SIGNING['kid'],
            issuer=TEST_CALLER_SIGNING['issuer'],
        )

    def _post(self, body: dict):
        base = {'grant_version': 0}
        base.update(body)
        return self.client.post(
            _PATH,
            data=json.dumps(base),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion()}',
        )

    def test_accepts_strict_mcp_path(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 12,
                'access_kind': 'read',
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 201, r.content)
        from apps.agents.models import McpCallLog

        log = McpCallLog.objects.get(pk=r.json()['id'])
        self.assertEqual(log.resource_label, 'POST /mcp (storage)')

    def test_empty_path_normalized_to_mcp(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 201)

    def test_rejects_arguments_payload(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'x',
                'arguments': {'a': 1},
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 400)

    def test_rejects_untrusted_path(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/users/1',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 400)

    def test_outcome_required(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
            }
        )
        self.assertEqual(r.status_code, 400)

    def test_rejects_non_int_company_id(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': True,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 400)

    def test_rejects_invalid_outcome(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'not_a_real_outcome',
            }
        )
        self.assertEqual(r.status_code, 400)

    def test_approval_id_requires_matching_action(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='list_buckets',
            arguments_hash='a' * 64,
            short_action_summary='x',
            expires_at=timezone.now() + __import__('datetime').timedelta(minutes=5),
            status=McpApprovalRequest.STATUS_APPROVED,
            **approval_authority_snapshot_for_agent(self.agent),
        )
        r_ok = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'approval_id': str(row.id),
            }
        )
        self.assertEqual(r_ok.status_code, 201)
        body = __import__('json').loads(r_ok.content.decode())
        from apps.agents.models import McpCallLog

        log = McpCallLog.objects.get(pk=body['id'])
        self.assertEqual(log.approval_id, row.id)

        r_bad = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'other_tool',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'approval_id': str(row.id),
            }
        )
        self.assertEqual(r_bad.status_code, 400, r_bad.content)

    def test_delegated_requires_binding_triplet(self):
        import uuid as uuid_mod

        gc = uuid_mod.uuid4()
        self.agent.global_agent_id = uuid_mod.uuid4()
        self.agent.global_company_id = gc
        self.agent.company_binding_version = 2
        self.agent.grant_version = 5
        self.agent.save(
            update_fields=[
                'global_agent_id',
                'global_company_id',
                'company_binding_version',
                'grant_version',
            ]
        )
        r_ok = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'grant_version': 5,
                'global_company_id': str(gc),
                'company_binding_version': 2,
            }
        )
        self.assertEqual(r_ok.status_code, 201, r_ok.content)
        r_conflict = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'grant_version': 5,
                'global_company_id': str(uuid_mod.uuid4()),
                'company_binding_version': 2,
            }
        )
        self.assertEqual(r_conflict.status_code, 409, r_conflict.content)

    def test_destructive_requires_approved_destructive_approval(self):
        self.agent.global_max_destructive = True
        self.agent.save(update_fields=['global_max_destructive'])
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='wipe_bucket',
            arguments_hash='b' * 64,
            short_action_summary='x',
            expires_at=timezone.now() + __import__('datetime').timedelta(minutes=5),
            status=McpApprovalRequest.STATUS_APPROVED,
            is_destructive=True,
            **approval_authority_snapshot_for_agent(self.agent),
        )
        r_ok = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'wipe_bucket',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'access_kind': 'destructive',
                'approval_id': str(row.id),
            }
        )
        self.assertEqual(r_ok.status_code, 201, r_ok.content)
        r_no_appr = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'wipe_bucket',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'access_kind': 'destructive',
            }
        )
        self.assertEqual(r_no_appr.status_code, 400, r_no_appr.content)


_GLOBAL = 'https://global.id.example'
_DASH_ISS = 'https://dashboard.example'
_IDENTITY = 'https://identity.test'


def _build_dashboard_call_log_assertion(*, private_pem: str, kid: str) -> str:
    now = int(time.time())
    claims = {
        'iss': _DASH_ISS,
        'aud': CALL_LOG_AUDIENCE,
        'sub': 'service',
        'scope': CALL_LOG_SCOPE,
        'target': _IDENTITY,
        'iat': now,
        'exp': now + 55,
        'jti': uuid.uuid4().hex,
    }
    token = jwt.encode(claims, private_pem, algorithm='RS256', headers={'kid': kid})
    return token.decode('utf-8') if isinstance(token, bytes) else token


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER=_IDENTITY,
    JWT_AUDIENCE='shellui-test',
    GLOBAL_ISSUER_URL=_GLOBAL,
    PROVISIONING_ISSUER=_DASH_ISS,
    AUTH_RATE_LIMIT_ENABLED=False,
    STORAGE_SERVICE_URL='https://storage.region.example',
)
class McpInternalGlobalCallLogTests(TestCase):
    """Dashboard-signed call log rows without a regional Agent (global_agent_id in body)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        priv, pub = generate_rsa_key_pair(2048)
        cls._dash_key = load_signing_key(private_pem=priv, public_pem=pub)
        cls._dash_jwks = build_jwks_document(cls._dash_key)

    def setUp(self):
        self.client = Client()
        self.company = Company.objects.create(name='Gbl Log Co', slug='gbl-log')
        self.owner = User.objects.create_user(username='gown', email='gown@gbl.test', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.gc = uuid.uuid4()
        ProvisionedCompany.objects.create(company=self.company, global_company_id=str(self.gc), limits_version=1)
        UpstreamAccount.objects.create(user=self.owner, issuer=_GLOBAL, sub='owner-sub-log', email=self.owner.email)
        self.ga = uuid.uuid4()

    def _settings(self):
        return override_settings(
            PROVISIONING_PUBLIC_KEY=self._dash_key.public_pem.decode('utf-8')
            if isinstance(self._dash_key.public_pem, bytes)
            else self._dash_key.public_pem,
        )

    def _post(self, body: dict):
        with self._settings():
            assertion = _build_dashboard_call_log_assertion(
                private_pem=self._dash_key.private_pem,
                kid=self._dash_key.kid,
            )
            return self.client.post(
                _PATH,
                data=json.dumps(body),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {assertion}',
            )

    def test_dashboard_global_creates_row_without_agent(self):
        r = self._post(
            {
                'company_id': self.company.pk,
                'global_agent_id': str(self.ga),
                'global_company_id': str(self.gc),
                'grant_version': 1,
                'company_binding_version': 1,
                'service': 'storage',
                'tool': 'list_files',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 5,
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 201, r.content)
        from apps.agents.models import McpCallLog

        log = McpCallLog.objects.get(pk=r.json()['id'])
        self.assertIsNone(log.agent_id)
        self.assertEqual(log.company_id, self.company.pk)

    def test_storage_caller_rejected_for_global_path(self):
        r = self.client.post(
            _PATH,
            data=json.dumps(
                {
                    'company_id': self.company.pk,
                    'global_agent_id': str(self.ga),
                    'global_company_id': str(self.gc),
                    'grant_version': 1,
                    'company_binding_version': 1,
                    'service': 'storage',
                    'tool': 'x',
                    'method': 'POST',
                    'path': '/mcp',
                    'status': 200,
                    'duration_ms': 1,
                    'outcome': 'allowed',
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {build_mcp_call_log_assertion(audience_url=_IDENTITY, **TEST_CALLER_SIGNING)}',
        )
        self.assertEqual(r.status_code, 403, r.content)

    def test_regional_path_rejects_stray_global_agent_id(self):
        agent = Agent.objects.create(
            company=self.company,
            name='Regional',
            created_by=self.owner,
            services_allowed=['storage'],
        )
        r = self.client.post(
            _PATH,
            data=json.dumps(
                {
                    'agent_id': str(agent.id),
                    'company_id': self.company.pk,
                    'global_agent_id': str(self.ga),
                    'service': 'storage',
                    'tool': 'list_buckets',
                    'method': 'POST',
                    'path': '/mcp',
                    'status': 200,
                    'duration_ms': 1,
                    'grant_version': 0,
                    'outcome': 'allowed',
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {build_mcp_call_log_assertion(audience_url=_IDENTITY, **TEST_CALLER_SIGNING)}',
        )
        self.assertEqual(r.status_code, 400, r.content)

    def test_global_approval_id_must_match(self):
        appr = McpApprovalRequest.objects.create(
            agent=None,
            company=None,
            service='storage',
            action='list_files',
            arguments_hash='f' * 64,
            status=McpApprovalRequest.STATUS_APPROVED,
            expires_at=timezone.now() + __import__('datetime').timedelta(minutes=5),
            global_agent_id=self.ga,
            global_company_id=self.gc,
            company_binding_version=1,
            global_user_sub='owner-sub-log',
            authority_grant_version=1,
            authority_global_company_id=self.gc,
            authority_company_binding_version=1,
        )
        r_bad = self._post(
            {
                'company_id': self.company.pk,
                'global_agent_id': str(self.ga),
                'global_company_id': str(self.gc),
                'grant_version': 1,
                'company_binding_version': 1,
                'service': 'storage',
                'tool': 'other_tool',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'approval_id': str(appr.id),
            }
        )
        self.assertEqual(r_bad.status_code, 400, r_bad.content)
        r_ok = self._post(
            {
                'company_id': self.company.pk,
                'global_agent_id': str(self.ga),
                'global_company_id': str(self.gc),
                'grant_version': 1,
                'company_binding_version': 1,
                'service': 'storage',
                'tool': 'list_files',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'approval_id': str(appr.id),
            }
        )
        self.assertEqual(r_ok.status_code, 201, r_ok.content)
