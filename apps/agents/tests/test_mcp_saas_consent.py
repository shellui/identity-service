"""Optional SaaS access at MCP consent (saas_offered, global sign-in, regional agent)."""

from __future__ import annotations

from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.agents.models import Agent
from apps.agents.tests.test_mcp_company_signin import CompanySigninFlowTests, SETTINGS
from apps.authapi.client_pkce import s256_challenge
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.federation.tests.test_federation import ISSUER, _CryptoMixin

User = get_user_model()

REGION = 'https://identity.test'
SAAS_SETTINGS = {
    **SETTINGS,
    'JWT_ISSUER': REGION,
    'SAAS_SERVICE_URL': 'https://saas.test',
    'SHELLUI_INSTANCE_ROLE': 'region',
    'GLOBAL_ISSUER_URL': ISSUER,
    'GLOBAL_CLIENT_ID': 'region-app',
    'GLOBAL_CLIENT_SECRET': 'region-secret-value',
    'GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE': 'shellui-global-agents',
}


@override_settings(**SAAS_SETTINGS)
class McpSaasConsentUiTests(CompanySigninFlowTests):
    def test_saas_checkbox_only_when_offered(self):
        self.client.force_login(self.user)
        self.client.post(self._query(), {'account_choice': 'continue'})
        without = self.client.get(self._query())
        self.assertNotContains(without, 'name="include_saas"')
        with_offer = self.client.get(self._query(saas_offered='1'))
        self.assertContains(with_offer, 'name="include_saas"')
        self.assertNotContains(with_offer, 'value="saas"')

    @override_settings(**{**SAAS_SETTINGS, 'GLOBAL_JWKS': {}})
    def test_include_saas_without_exchange_adds_service_on_approve(self):
        self.client.force_login(self.user)
        approved = self.client.post(
            self._query(saas_offered='1'),
            {**self._form(), 'decision': 'approve', 'include_saas': 'on'},
        )
        self.assertEqual(approved.status_code, 302)
        agent = Agent.objects.get()
        self.assertIn('saas', agent.services_allowed)


@override_settings(**SAAS_SETTINGS)
class McpSaasGlobalSigninTests(_CryptoMixin, CompanySigninFlowTests):
    def setUp(self):
        super().setUp()
        self._enable(
            SHELLUI_INSTANCE_ROLE='region',
            JWT_ISSUER=REGION,
            GLOBAL_ISSUER_URL=ISSUER,
            GLOBAL_JWKS=self.jwks,
            GLOBAL_CLIENT_ID='region-app',
            GLOBAL_CLIENT_SECRET='region-secret-value',
            GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE='shellui-global-agents',
            SAAS_SERVICE_URL='https://saas.test',
        )

    def test_include_saas_redirects_to_global_authorize(self):
        self.client.force_login(self.user)
        response = self.client.post(
            self._query(saas_offered='1'),
            {**self._form(), 'decision': 'approve', 'include_saas': 'on'},
        )
        self.assertEqual(response.status_code, 302)
        location = response['Location']
        self.assertTrue(location.startswith(f'{ISSUER}/oauth/authorize?'))
        params = parse_qs(urlsplit(location).query)
        self.assertEqual(params.get('prompt'), ['login'])
        state = params['state'][0]
        saved = cache.get(f'mcp:saas-upstream:{state}')
        self.assertIsInstance(saved, dict)
        self.assertEqual(saved.get('company_id'), self.company.id)

    def test_saas_return_completes_consent_after_global_signin(self):
        self.client.force_login(self.user)
        redirect = self.client.post(
            self._query(saas_offered='1'),
            {**self._form(), 'decision': 'approve', 'include_saas': 'on'},
        )
        state = parse_qs(urlsplit(redirect['Location']).query)['state'][0]
        saved = cache.get(f'mcp:saas-upstream:{state}')
        claims = {
            'iss': ISSUER,
            'sub': 'upstream-sub-1',
            'email': self.user.email,
            'email_verified': True,
            'nonce': saved['nonce'],
        }
        with patch('apps.agents.mcp_saas_return._exchange', return_value='id.jwt'), patch(
            'apps.agents.mcp_saas_return.verify_pinned', return_value=claims
        ):
            done = self.client.get(f'/oauth/mcp/saas-return?code=abc&state={state}')
        self.assertEqual(done.status_code, 302)
        self.assertTrue(done['Location'].startswith('https://chatgpt.com/connector_platform_oauth_redirect?'))
        agent = Agent.objects.get()
        self.assertIn('saas', agent.services_allowed)
        self.assertIn('ai', agent.services_allowed)

    def test_staff_refused_when_opting_into_saas(self):
        staff = User.objects.create_user(username='st', email='st@acme.com', password='unused', is_staff=True)
        set_company_access(self.company, staff, enabled=True)
        self.client.force_login(staff)
        response = self.client.post(
            self._query(saas_offered='1'),
            {**self._form(), 'decision': 'approve', 'include_saas': 'on'},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Agent.objects.count(), 0)
