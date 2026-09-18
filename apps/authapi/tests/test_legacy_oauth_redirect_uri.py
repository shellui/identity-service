from unittest.mock import patch

from allauth.socialaccount.models import SocialApp
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
)
class LegacyOAuthRedirectUriAllowlistTests(TestCase):
    """Legacy social/exchange endpoints must enforce the same redirect allowlist as redirect_to."""

    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Legacy OAuth Co', slug='legacy-oauth-co')
        self.app = SocialApp.objects.create(
            provider='github',
            name='GitHub Test',
            client_id='cid',
            secret='csecret',
        )
        self.oauth_client = CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.app,
            is_active=True,
        )
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )
        self.allowed_redirect_uri = 'https://shell.example.com/login/callback'
        self.evil_redirect_uri = 'https://evil.example.com/login/callback'
        self.loopback_redirect_uri = 'http://127.0.0.1:8765/login/callback'

    def test_social_authorize_rejects_non_allowlisted_redirect_uri(self):
        response = self.client.get(
            '/api/v1/providers/github/authorize/',
            {
                'company_id': self.company.id,
                'redirect_uri': self.evil_redirect_uri,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('not allowed', str(response.data.get('error', '')).lower())

    def test_social_authorize_allows_allowlisted_redirect_uri(self):
        response = self.client.get(
            '/api/v1/providers/github/authorize/',
            {
                'company_id': self.company.id,
                'redirect_uri': self.allowed_redirect_uri,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('authorize_url', response.data)

    def test_social_authorize_allows_loopback_without_allowlist_row(self):
        CompanyOAuthRedirect.objects.all().delete()
        response = self.client.get(
            '/api/v1/providers/github/authorize/',
            {
                'company_id': self.company.id,
                'redirect_uri': self.loopback_redirect_uri,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('authorize_url', response.data)

    @patch('apps.authapi.views.exchange_code_for_token', return_value='provider-access')
    @patch(
        'apps.authapi.views.fetch_provider_userinfo',
        return_value={'id': 1, 'login': 'octocat', 'email': 'octocat@example.com', 'name': 'Octo Cat'},
    )
    def test_social_login_rejects_non_allowlisted_redirect_uri(self, _userinfo, _exchange):
        response = self.client.post(
            f'/api/v1/providers/github/login/?company_id={self.company.id}',
            {
                'code': 'auth-code',
                'redirect_uri': self.evil_redirect_uri,
            },
            format='json',
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('not allowed', str(response.data.get('error', '')).lower())
        self.assertFalse(_exchange.called)

    @patch('apps.authapi.views.exchange_code_for_token', return_value='provider-access')
    @patch(
        'apps.authapi.views.fetch_provider_userinfo',
        return_value={'id': 1, 'login': 'octocat', 'email': 'octocat@example.com', 'name': 'Octo Cat'},
    )
    def test_social_login_allows_allowlisted_redirect_uri(self, _userinfo, exchange):
        response = self.client.post(
            f'/api/v1/providers/github/login/?company_id={self.company.id}',
            {
                'code': 'auth-code',
                'redirect_uri': self.allowed_redirect_uri,
            },
            format='json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(exchange.called)

    @patch('apps.authapi.views.exchange_code_for_token', return_value='provider-access')
    @patch(
        'apps.authapi.views.fetch_provider_userinfo',
        return_value={'id': 1, 'login': 'octocat', 'email': 'octocat@example.com', 'name': 'Octo Cat'},
    )
    def test_oauth_exchange_rejects_non_allowlisted_redirect_uri(self, _userinfo, _exchange):
        response = self.client.post(
            f'/api/v1/oauth/exchange?company_id={self.company.id}',
            {
                'provider': 'github',
                'code': 'auth-code',
                'redirect_uri': self.evil_redirect_uri,
            },
            format='json',
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('not allowed', str(response.data.get('error', '')).lower())
        self.assertFalse(_exchange.called)

    @patch('apps.authapi.views.exchange_code_for_token', return_value='provider-access')
    @patch(
        'apps.authapi.views.fetch_provider_userinfo',
        return_value={'id': 1, 'login': 'octocat', 'email': 'octocat@example.com', 'name': 'Octo Cat'},
    )
    def test_oauth_exchange_allows_allowlisted_redirect_uri(self, _userinfo, exchange):
        response = self.client.post(
            f'/api/v1/oauth/exchange?company_id={self.company.id}',
            {
                'provider': 'github',
                'code': 'auth-code',
                'redirect_uri': self.allowed_redirect_uri,
            },
            format='json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(exchange.called)
