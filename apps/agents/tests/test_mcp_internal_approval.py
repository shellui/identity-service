import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.agents.models import Agent, McpApprovalRequest, McpOAuthClient
from shellui_mcp.internal import build_mcp_approval_assertion, build_mcp_call_log_assertion

User = get_user_model()

IDENTITY_ORIGIN = 'https://identity.test'


def _approval_assertion(agent, *, service='storage', action='write_tool', args_hash='abc123'):
    return build_mcp_approval_assertion(
        company_id=agent.company_id,
        agent_id=str(agent.id),
        service=service,
        action=action,
        arguments_hash=args_hash,
        audience_url=IDENTITY_ORIGIN,
    )


@override_settings(
    JWT_ISSUER=IDENTITY_ORIGIN,
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpInternalApprovalStateTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='State Co', slug='state-co')
        self.owner = User.objects.create_user(username='state-owner', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        client_row = McpOAuthClient.objects.create(client_id='cid-state', redirect_uris=['http://127.0.0.1/cb'])
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            oauth_client=client_row,
            created_by=self.owner,
            services_allowed=['storage'],
        )
        self.args_hash = 'deadbeef' * 4

    def _state(self, *, service='storage', action='write_tool', args_hash=None, extra_body=None):
        args_hash = args_hash or self.args_hash
        assertion = _approval_assertion(self.agent, service=service, action=action, args_hash=args_hash)
        body = {
            'agent_id': str(self.agent.id),
            'company_id': self.company.id,
            'service': service,
            'action': action,
            'arguments_hash': args_hash,
        }
        if extra_body:
            body.update(extra_body)
        return self.client.post(
            '/api/v1/mcp/internal/mcp-approval-state',
            data=json.dumps(body),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )

    def test_state_unknown_returns_404(self):
        response = self._state()
        self.assertEqual(response.status_code, 404)

    def test_state_pending_and_approved(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_tool',
            arguments_hash=self.args_hash,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        pending = self._state()
        self.assertEqual(pending.status_code, 200)
        self.assertEqual(pending.json()['status'], 'pending')

        row.status = McpApprovalRequest.STATUS_APPROVED
        row.save(update_fields=['status'])
        approved = self._state()
        self.assertEqual(approved.status_code, 200)
        data = approved.json()
        self.assertEqual(data['status'], 'approved')
        self.assertEqual(data['id'], str(row.id))

    def test_state_denied(self):
        McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_tool',
            arguments_hash=self.args_hash,
            status=McpApprovalRequest.STATUS_REJECTED,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        response = self._state()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'denied')

    def test_state_expired(self):
        McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_tool',
            arguments_hash=self.args_hash,
            status=McpApprovalRequest.STATUS_APPROVED,
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        response = self._state()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'expired')

    def test_state_args_mismatch_rejected(self):
        McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_tool',
            arguments_hash=self.args_hash,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        response = self._state(extra_body={'arguments_hash': 'otherhash' * 4})
        self.assertEqual(response.status_code, 400)

    def test_state_wrong_service_in_assertion(self):
        McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_tool',
            arguments_hash=self.args_hash,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        response = self._state(service='hosting')
        self.assertEqual(response.status_code, 404)


@override_settings(
    JWT_ISSUER=IDENTITY_ORIGIN,
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpInternalApprovalConsumeTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Consume Co', slug='consume-co')
        self.owner = User.objects.create_user(username='consume-owner', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        client_row = McpOAuthClient.objects.create(client_id='cid-consume', redirect_uris=['http://127.0.0.1/cb'])
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            oauth_client=client_row,
            created_by=self.owner,
            services_allowed=['storage'],
        )

    def _consume(self, row_id, *, use_path=False, body_key='approval_id'):
        assertion = build_mcp_call_log_assertion(audience_url=IDENTITY_ORIGIN)
        if use_path:
            url = f'/api/v1/mcp/internal/mcp-approval-consume/{row_id}'
            return self.client.post(url, HTTP_AUTHORIZATION=f'Bearer {assertion}')
        return self.client.post(
            '/api/v1/mcp/internal/mcp-approval-consume',
            data=json.dumps({body_key: str(row_id)}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )

    def test_consume_success_once(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_tool',
            arguments_hash='hash1',
            status=McpApprovalRequest.STATUS_APPROVED,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        first = self._consume(row.id)
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json()['consumed'])
        second = self._consume(row.id)
        self.assertEqual(second.status_code, 409)
        self.assertFalse(second.json()['consumed'])

    def test_consume_via_path_and_id_body_key(self):
        path_row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_tool',
            arguments_hash='hash2a',
            status=McpApprovalRequest.STATUS_APPROVED,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        path_resp = self._consume(path_row.id, use_path=True)
        self.assertEqual(path_resp.status_code, 200)
        self.assertTrue(path_resp.json()['consumed'])

        id_row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_tool',
            arguments_hash='hash2b',
            status=McpApprovalRequest.STATUS_APPROVED,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        id_resp = self._consume(id_row.id, body_key='id')
        self.assertEqual(id_resp.status_code, 200)
        self.assertTrue(id_resp.json()['consumed'])

    def test_consume_denied_or_expired_fails(self):
        denied = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_tool',
            arguments_hash='hash3',
            status=McpApprovalRequest.STATUS_REJECTED,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        denied_resp = self._consume(denied.id)
        self.assertEqual(denied_resp.status_code, 409)
        self.assertFalse(denied_resp.json()['consumed'])

        expired = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_tool',
            arguments_hash='hash4',
            status=McpApprovalRequest.STATUS_APPROVED,
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        expired_resp = self._consume(expired.id)
        self.assertEqual(expired_resp.status_code, 409)
        self.assertFalse(expired_resp.json()['consumed'])
