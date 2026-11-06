import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.agents.tests.mcp_test_settings import (
    TEST_CALLER_SIGNING,
    TRUSTED_TEST_CALLER_SETTINGS,
    approval_authority_snapshot_for_agent,
    build_mcp_approval_assertion_for_agent,
)
from apps.agents.tests.mcp_test_settings import rs256_identity_settings
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.agents.models import Agent, McpApprovalRequest, McpCallLog, McpOAuthClient
from apps.agents.tokens import encode_access_token
from shellui_django.mcp.internal import build_mcp_revocation_assertion

User = get_user_model()

IDENTITY_ORIGIN = 'https://identity.test'
IDENTITY_MCP_RESOURCE = 'https://identity.test/mcp'


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER=IDENTITY_ORIGIN,
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpTenantIsolationTests(TestCase):
    def setUp(self):
        self.company_a = Company.objects.create(name='Company A', slug='company-a')
        self.company_b = Company.objects.create(name='Company B', slug='company-b')
        self.owner_a = User.objects.create_user(username='owner-a', password='unused')
        self.owner_b = User.objects.create_user(username='owner-b', password='unused')
        self.company_a.owners.add(self.owner_a)
        self.company_b.owners.add(self.owner_b)
        set_company_access(self.company_a, self.owner_a, enabled=True)
        set_company_access(self.company_b, self.owner_b, enabled=True)
        client_row = McpOAuthClient.objects.create(client_id='cid-iso', redirect_uris=['http://127.0.0.1/cb'])
        self.agent_a = Agent.objects.create(
            company=self.company_a,
            name='Agent A',
            oauth_client=client_row,
            created_by=self.owner_a,
            services_allowed=['identity', 'storage'],
        )
        self.agent_b = Agent.objects.create(
            company=self.company_b,
            name='Agent B',
            oauth_client=client_row,
            created_by=self.owner_b,
            services_allowed=['identity', 'storage'],
        )
        self.agent_token_a = encode_access_token(self.agent_a, resource=IDENTITY_MCP_RESOURCE)

    def _approval_assertion(self, agent, *, company_id=None, service='storage', args_hash='abc'):
        return build_mcp_approval_assertion_for_agent(
            agent,
            **TEST_CALLER_SIGNING,
            company_id=company_id if company_id is not None else agent.company_id,
            agent_id=str(agent.id),
            service=service,
            action='write_tool',
            arguments_hash=args_hash,
            audience_url=IDENTITY_ORIGIN,
        )

    def test_agent_cannot_list_company_b_agents(self):
        response = self.client.get(
            '/api/v1/mcp/agents',
            HTTP_AUTHORIZATION=f'Bearer {self.agent_token_a}',
        )
        self.assertEqual(response.status_code, 403)

    def test_agent_cannot_pause_company_b_agent(self):
        response = self.client.post(
            f'/api/v1/mcp/agents/{self.agent_b.id}/pause',
            HTTP_AUTHORIZATION=f'Bearer {self.agent_token_a}',
        )
        self.assertEqual(response.status_code, 403)

    def test_agent_cannot_revoke_own_or_other_agent(self):
        for agent_id in (self.agent_a.id, self.agent_b.id):
            response = self.client.post(
                f'/api/v1/mcp/agents/{agent_id}/revoke',
                HTTP_AUTHORIZATION=f'Bearer {self.agent_token_a}',
            )
            self.assertEqual(response.status_code, 403, agent_id)

    def test_agent_cannot_approve_company_b_request(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent_b,
            company=self.company_b,
            service='storage',
            action='write_tool',
            arguments_hash='hash-b',
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        response = self.client.post(
            f'/api/v1/mcp/approvals/{row.id}/approve',
            HTTP_AUTHORIZATION=f'Bearer {self.agent_token_a}',
        )
        self.assertEqual(response.status_code, 403)

    def test_agent_cannot_list_company_b_call_logs(self):
        McpCallLog.objects.create(
            agent=self.agent_b,
            company=self.company_b,
            service='storage',
            tool='t',
            http_method='GET',
            path='/x',
        )
        response = self.client.get(
            '/api/v1/mcp/call-logs',
            HTTP_AUTHORIZATION=f'Bearer {self.agent_token_a}',
        )
        self.assertEqual(response.status_code, 403)

    def test_internal_consume_rejects_cross_company_binding(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent_b,
            company=self.company_b,
            service='storage',
            action='write_tool',
            arguments_hash='hash-consume',
            status=McpApprovalRequest.STATUS_APPROVED,
            expires_at=timezone.now() + timedelta(minutes=10),
            **approval_authority_snapshot_for_agent(self.agent_b),
        )
        assertion = self._approval_assertion(self.agent_a, company_id=self.company_a.id)
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-consume',
            data=json.dumps({'approval_id': str(row.id)}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        self.assertEqual(response.status_code, 404)

    def test_revocation_company_filter_does_not_leak_other_tenant(self):
        self.agent_b.revoked_at = timezone.now()
        self.agent_b.save(update_fields=['revoked_at'])
        assertion = build_mcp_revocation_assertion(audience_url=IDENTITY_ORIGIN, **TEST_CALLER_SIGNING)
        with rs256_identity_settings():
            response = self.client.get(
                f'/api/v1/mcp/internal/mcp-revocations?company_id={self.company_a.id}',
                HTTP_AUTHORIZATION=f'Bearer {assertion}',
            )
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertNotIn(str(self.agent_b.id), data['revoked_agent_ids'])
            agent_ids = {entry['agent_id'] for entry in data.get('agents') or []}
            self.assertNotIn(str(self.agent_b.id), agent_ids)
