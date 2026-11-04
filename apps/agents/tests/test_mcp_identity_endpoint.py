"""Identity ``/mcp`` exposes local tools only (no aggregated gateway)."""

from __future__ import annotations

import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.agents.models import Agent
from apps.agents.tokens import encode_access_token
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

IDENTITY_MCP = 'https://identity.test/mcp'


def _rpc(method: str, **params):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}
    return json.dumps(body)


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    STORAGE_SERVICE_URL='https://storage.test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpIdentityEndpointTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Local Co', slug='local-co')
        self.owner = User.objects.create_user(username='local-owner', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            created_by=self.owner,
            services_allowed=['identity', 'storage'],
        )
        self.token = encode_access_token(self.agent, resource=IDENTITY_MCP)

    @patch('requests.post')
    def test_tools_list_does_not_call_downstream_services(self, post):
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
        )
        self.assertEqual(response.status_code, 200)
        post.assert_not_called()
        names = {t['name'] for t in response.json()['result']['tools']}
        self.assertIn('api_v1_mcp_services_list', names)

    @patch('requests.post')
    def test_agent_claims_as_plain_dict_are_accepted(self, post):
        """The RS256 agent path authenticates with a claims dict, not a simplejwt token object."""
        import jwt

        claims = jwt.decode(self.token, options={'verify_signature': False})
        with patch(
            'apps.agents.mcp_views.ShellUIJWTAuthentication.authenticate',
            return_value=(self.owner, dict(claims)),
        ):
            response = self.client.post(
                '/mcp',
                data=_rpc('tools/list'),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {self.token}',
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn('result', response.json())

    def test_agent_claims_for_another_resource_are_refused(self):
        import jwt

        other = encode_access_token(self.agent, resource='https://storage.test/mcp')
        claims = jwt.decode(other, options={'verify_signature': False})
        with patch(
            'apps.agents.mcp_views.ShellUIJWTAuthentication.authenticate',
            return_value=(self.owner, dict(claims)),
        ):
            response = self.client.post(
                '/mcp',
                data=_rpc('tools/list'),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {other}',
            )
        self.assertNotIn('result', response.json() if response.status_code == 200 else {})

