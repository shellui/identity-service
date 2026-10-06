from unittest.mock import MagicMock, patch

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from apps.authapi.oauth import build_authorize_url, exchange_code_for_token
from apps.authapi.oauth_user import extract_oauth_profile, resolve_oauth_user
from apps.companies.models import Company, CompanyOAuthClient

User = get_user_model()


class OAuthAllauthFlowTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.company = Company.objects.create(name='Allauth Co', slug='allauth-co')
        self.github_app = SocialApp.objects.create(
            provider='github',
            name='gh',
            client_id='cid',
            secret='secret',
            settings={'catalog_slug': 'github'},
        )
        self.github_client = CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.github_app,
            is_active=True,
        )

    @patch('apps.authapi.oauth.build_allauth_authorize_url')
    def test_github_authorize_uses_allauth_bridge(self, mocked):
        mocked.return_value = 'https://github.com/login/oauth/authorize?state=abc'
        request = self.factory.get('/api/v1/authorize')
        url = build_authorize_url(
            'github',
            redirect_uri='https://auth.example.com/api/v1/oauth/callback',
            state='signed-state',
            request=request,
            company_id=self.company.id,
            company_oauth_client_id=self.github_client.id,
        )
        self.assertIn('github.com', url)
        self.assertEqual(mocked.call_count, 1)

    @patch('apps.authapi.oauth.exchange_allauth_code')
    def test_github_exchange_uses_allauth(self, mocked):
        sociallogin = MagicMock()
        sociallogin.account.uid = 'gh-1'
        sociallogin.account.extra_data = {'id': 1, 'login': 'octo'}
        sociallogin.user.email = 'octo@example.com'
        sociallogin.user.get_full_name.return_value = 'Octo'
        mocked.return_value = (sociallogin, {'access_token': 'at'})
        request = self.factory.get('/api/v1/oauth/callback', {'code': 'the-code'})
        bundle = exchange_code_for_token(
            'github',
            code='the-code',
            redirect_uri='https://auth.example.com/api/v1/oauth/callback',
            request=request,
            company_id=self.company.id,
            company_oauth_client_id=self.github_client.id,
        )
        self.assertEqual(bundle.access_token, 'at')
        self.assertEqual(mocked.call_count, 1)
