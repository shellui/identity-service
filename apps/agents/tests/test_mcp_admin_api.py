import json

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.agents.models import Agent, McpOAuthClient
from shellui_django.mcp.internal import build_mcp_approval_assertion

User = get_user_model()


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpAdminApiTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-mcp-admin')
        self.owner = User.objects.create_user(username='owner2', email='o2@acme.com', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.agent = Agent.objects.create(company=self.company, name='A1', created_by=self.owner)

    def _owner_token(self):
        from apps.authapi.views import _issue_shellui_tokens

        return _issue_shellui_tokens(self.owner, company=self.company)['access_token']

    def test_list_agents_requires_owner(self):
        response = self.client.get('/api/v1/mcp/agents')
        self.assertEqual(response.status_code, 401)
        token = self._owner_token()
        response = self.client.get('/api/v1/mcp/agents', HTTP_AUTHORIZATION=f'Bearer {token}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['agents']), 1)

    def test_pause_agent(self):
        token = self._owner_token()
        response = self.client.post(
            f'/api/v1/mcp/agents/{self.agent.id}/pause',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 200)
        self.agent.refresh_from_db()
        self.assertIsNotNone(self.agent.paused_at)

    def test_staff_refused_on_mcp_admin_api(self):
        staff = User.objects.create_user(username='staff-mcp', password='unused', is_staff=True)
        self.company.owners.add(staff)
        set_company_access(self.company, staff, enabled=True)
        from apps.authapi.views import _issue_shellui_tokens

        token = _issue_shellui_tokens(staff, company=self.company)['access_token']
        response = self.client.get('/api/v1/mcp/agents', HTTP_AUTHORIZATION=f'Bearer {token}')
        self.assertEqual(response.status_code, 403)

    def test_approval_list_masks_secret_arguments(self):
        oauth_client = McpOAuthClient.objects.create(
            client_id='cid-admin-approval',
            redirect_uris=['http://127.0.0.1/cb'],
        )
        agent = Agent.objects.create(
            company=self.company,
            name='Writer',
            oauth_client=oauth_client,
            created_by=self.owner,
            services_allowed=['storage'],
        )
        args_hash = 'cafebabe' * 8
        assertion = build_mcp_approval_assertion(
            company_id=self.company.id,
            agent_id=str(agent.id),
            service='storage',
            action='delete_object',
            arguments_hash=args_hash,
            audience_url='https://identity.test',
        )
        create = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-requests',
            data=json.dumps(
                {
                    'arguments': {'api_key': 'super-secret-value', 'object_name': 'report.pdf'},
                    'target': 'POST /api/v1/objects/delete',
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        self.assertEqual(create.status_code, 200)
        owner_token = self._owner_token()
        listed = self.client.get('/api/v1/mcp/approvals', HTTP_AUTHORIZATION=f'Bearer {owner_token}')
        self.assertEqual(listed.status_code, 200)
        approvals = listed.json()['approvals']
        self.assertEqual(len(approvals), 1)
        row = approvals[0]
        self.assertEqual(row['service'], 'storage')
        self.assertEqual(row['action'], 'delete_object')
        self.assertEqual(row['target'], 'POST /api/v1/objects/delete')
        self.assertEqual(row['arguments_redacted']['api_key'], '[redacted]')
        self.assertEqual(row['arguments_redacted']['object_name'], 'report.pdf')
        detail = self.client.get(
            f'/api/v1/mcp/approvals/{row["id"]}',
            HTTP_AUTHORIZATION=f'Bearer {owner_token}',
        )
        self.assertEqual(detail.status_code, 200)
        approval = detail.json()['approval']
        self.assertEqual(approval['arguments_redacted']['api_key'], '[redacted]')
        self.assertEqual(approval['target'], 'POST /api/v1/objects/delete')
