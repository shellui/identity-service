"""Internal MCP call log ingest (signed assertions, strict path and body rules)."""

from __future__ import annotations

import json
import uuid

import jwt
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from shellui_django.mcp.internal import CALL_LOG_AUDIENCE, CALL_LOG_SCOPE, build_mcp_call_log_assertion

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
