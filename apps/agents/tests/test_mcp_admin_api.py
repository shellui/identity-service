from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.agents.models import Agent

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
