import json

import jwt
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from apps.authapi.client_pkce import s256_challenge
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.agents.models import Agent
from apps.agents.tokens import encode_access_token

User = get_user_model()

IDENTITY_MCP_RESOURCE = 'https://identity.test/mcp'
STORAGE_MCP_RESOURCE = 'https://storage.test/mcp'


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    STORAGE_SERVICE_URL='https://storage.test',
    AUTH_RATE_LIMIT_ENABLED=False,
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
)
class McpResourceOAuthTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Resource Co', slug='resource-co')
        self.owner = User.objects.create_user(username='res-owner', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            created_by=self.owner,
            services_allowed=['identity', 'storage'],
        )

    def test_access_token_audience_is_resource_url(self):
        token = encode_access_token(self.agent, resource=IDENTITY_MCP_RESOURCE)
        payload = jwt.decode(token, options={'verify_signature': False})
        self.assertEqual(payload['aud'], IDENTITY_MCP_RESOURCE)

    def test_mcp_endpoint_rejects_wrong_resource_audience(self):
        token = encode_access_token(self.agent, resource=STORAGE_MCP_RESOURCE)
        response = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 401)
