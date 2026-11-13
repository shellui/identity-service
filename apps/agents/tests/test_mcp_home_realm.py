"""MCP sign-in email-first home realm discovery."""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.test import Client, TestCase, override_settings

from apps.agents.mcp_home_realm import resolve_home_realm_client
from apps.authapi.client_pkce import s256_challenge
from apps.agents.models import McpOAuthClient
from apps.companies.models import Company, CompanyOAuthClient

User = get_user_model()

SETTINGS = dict(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AI_SERVICE_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect'


@override_settings(**SETTINGS)
class HomeRealmResolutionTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(
            name='Acme',
            slug='acme-realm',
            verified_email_domains=['acme.com'],
            enable_magic_link=True,
        )
        site = Site.objects.get_current()
        self.app = SocialApp.objects.create(
            provider='saml',
            name='acme-saml',
            client_id='acme-org',
            secret='-',
            settings={'created_by_company_id': self.company.id},
        )
        self.app.sites.add(site)
        self.client_row = CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.app,
            is_active=True,
            sso_verified_domains=['acme.com'],
        )

    def test_resolve_requires_shellui_verified_domain(self):
        self.assertIsNotNone(resolve_home_realm_client(self.company, 'acme.com'))
        self.assertIsNone(resolve_home_realm_client(self.company, 'other.com'))

    def test_unknown_company_id_same_page_no_realm_redirect(self):
        client = Client()
        oauth = McpOAuthClient.objects.create(
            client_id='realm-client',
            redirect_uris=[REDIRECT],
        )
        resource = 'https://ai.test/c/999999/mcp'
        query = urlencode(
            {
                'response_type': 'code',
                'client_id': oauth.client_id,
                'redirect_uri': REDIRECT,
                'code_challenge': s256_challenge('w' * 43),
                'code_challenge_method': 'S256',
                'resource': resource,
            }
        )
        client.get('/oauth/mcp/authorize?' + query)
        response = client.post('/oauth/mcp/signin', {'email': 'user@acme.com'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('/api/v1/', response.content.decode())

    def test_verified_domain_redirects_to_company_sso(self):
        oauth = McpOAuthClient.objects.create(client_id='c-realm', redirect_uris=[REDIRECT])
        query = urlencode(
            {
                'response_type': 'code',
                'client_id': oauth.client_id,
                'redirect_uri': REDIRECT,
                'code_challenge': s256_challenge('w' * 43),
                'code_challenge_method': 'S256',
                'resource': f'https://ai.test/c/{self.company.id}/mcp',
            }
        )
        client = Client()
        client.get('/oauth/mcp/authorize?' + query)
        response = client.post('/oauth/mcp/signin', {'email': 'u@acme.com'})
        self.assertEqual(response.status_code, 302)
        location = response['Location']
        self.assertIn('/api/v1/authorize', location)
        params = parse_qs(urlparse(location).query)
        self.assertEqual(params.get('company_id'), [str(self.company.id)])
        self.assertIn('redirect_to', params)
        self.assertIn('/oauth/mcp/signin/complete', params['redirect_to'][0])

    def test_non_verified_domain_gets_generic_magic_link_page(self):
        from unittest import mock

        oauth = McpOAuthClient.objects.create(client_id='c-realm2', redirect_uris=[REDIRECT])
        query = urlencode(
            {
                'response_type': 'code',
                'client_id': oauth.client_id,
                'redirect_uri': REDIRECT,
                'code_challenge': s256_challenge('w' * 43),
                'code_challenge_method': 'S256',
                'resource': f'https://ai.test/c/{self.company.id}/mcp',
            }
        )
        client = Client()
        client.get('/oauth/mcp/authorize?' + query)
        with mock.patch('apps.authapi.magic_link_views.deliver_magic_link_email'):
            response = client.post('/oauth/mcp/signin', {'email': 'user@gmail.com'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'sign-in link is on its way')
