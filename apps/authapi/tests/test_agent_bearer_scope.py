"""Agent JWTs are bearers only on POST /mcp, and only as access tokens."""

from __future__ import annotations

import json

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework_simplejwt.settings import api_settings

from apps.agents.models import Agent
from apps.agents.tests.mcp_test_settings import McpEndpointSigningMixin
from apps.agents.tokens import encode_access_token, issue_agent_refresh
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()
ISSUER = 'https://identity.test'
RESOURCE = 'https://identity.test/mcp'


def _with_aud(raw: str) -> str:
    """Refresh JWTs must carry aud or the agent decoder never sees them."""
    claims = jwt.decode(raw, options={'verify_signature': False})
    claims.setdefault('aud', 'shellui-test')
    claims.setdefault('iss', ISSUER)
    token = jwt.encode(claims, api_settings.SIGNING_KEY, algorithm=api_settings.ALGORITHM)
    return token.decode() if isinstance(token, bytes) else token


@override_settings(
    JWT_ISSUER=ISSUER,
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class AgentBearerScopeTests(McpEndpointSigningMixin, TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme-agent-bearer')
        self.owner = User.objects.create_user(username='owner-agent', email='owner@acme.test', password='unused')
        self.member = User.objects.create_user(username='member-agent', email='member@acme.test', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.member, enabled=True)
        self.owner_agent = Agent.objects.create(
            company=self.company,
            name='Owner agent',
            created_by=self.owner,
            services_allowed=['identity'],
        )
        self.member_agent = Agent.objects.create(company=self.company, name='Member agent', created_by=self.member)
        self.url = f'/api/v1/companies/{self.company.pk}/'

    def _patch(self, token, name='Renamed'):
        return self.client.patch(
            self.url,
            {'name': name},
            format='json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )

    def test_owner_agent_access_token_is_refused_on_the_company_admin_api(self):
        token = encode_access_token(self.owner_agent, resource=RESOURCE)
        response = self._patch(token)
        self.assertEqual(response.status_code, 401)
        self.company.refresh_from_db()
        self.assertEqual(self.company.name, 'Acme')

    def test_member_agent_is_not_promoted_to_owner(self):
        token = encode_access_token(self.member_agent, resource=RESOURCE)
        response = self._patch(token, name='Member rename')
        self.assertEqual(response.status_code, 401)
        human = _issue_shellui_tokens(self.member, company=self.company)['access_token']
        refused = self._patch(human, name='Member rename')
        self.assertEqual(refused.status_code, 403)
        self.company.refresh_from_db()
        self.assertEqual(self.company.name, 'Acme')

    def test_human_access_token_can_still_update_the_company(self):
        token = _issue_shellui_tokens(self.owner, company=self.company)['access_token']
        response = self._patch(token, name='Owner rename')
        self.assertEqual(response.status_code, 200)
        self.company.refresh_from_db()
        self.assertEqual(self.company.name, 'Owner rename')

    def test_agent_refresh_token_is_refused_as_a_bearer(self):
        raw, _session = issue_agent_refresh(self.owner_agent, resource=RESOURCE)
        response = self._patch(_with_aud(raw), name='From refresh')
        self.assertEqual(response.status_code, 401)
        self.company.refresh_from_db()
        self.assertEqual(self.company.name, 'Acme')

    def test_revoked_agent_refresh_token_is_refused_as_a_bearer(self):
        raw, session = issue_agent_refresh(self.owner_agent, resource=RESOURCE)
        session.revoked_at = timezone.now()
        session.save(update_fields=['revoked_at'])
        response = self._patch(_with_aud(raw))
        self.assertEqual(response.status_code, 401)

    def test_agent_access_token_is_accepted_on_the_mcp_endpoint(self):
        token = encode_access_token(self.owner_agent, resource=RESOURCE)
        response = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn('protocolVersion', response.json()['result'])

    def test_agent_refresh_token_is_refused_on_the_mcp_endpoint(self):
        raw, _session = issue_agent_refresh(self.owner_agent, resource=RESOURCE)
        response = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {_with_aud(raw)}',
        )
        self.assertEqual(response.status_code, 401)

    def test_user_refresh_token_is_refused_as_a_bearer(self):
        issued = _issue_shellui_tokens(self.owner, company=self.company)
        response = self._patch(issued['refresh_token'])
        self.assertEqual(response.status_code, 401)
