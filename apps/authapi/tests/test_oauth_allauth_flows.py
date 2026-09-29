from unittest.mock import MagicMock, patch

from allauth.socialaccount.models import SocialAccount, SocialApp
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from apps.authapi.oauth import build_authorize_url, exchange_code_for_token, fetch_provider_userinfo
from apps.authapi.oauth_user import extract_oauth_profile, resolve_oauth_user
from apps.authapi.provider_registry import get_provider_catalog
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
        self.discord_app = SocialApp.objects.create(
            provider='discord',
            name='discord',
            client_id='dcid',
            secret='dsecret',
            settings={'catalog_slug': 'discord'},
        )
        self.discord_client = CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.discord_app,
            is_active=True,
        )
        self.oidc_app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id='keycloak',
            name='kc',
            client_id='oidc-id',
            secret='oidc-secret',
            settings={'catalog_slug': 'keycloak', 'server_url': 'https://id.example.com/realms/test'},
        )
        self.oidc_client = CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.oidc_app,
            is_active=True,
        )

    @patch('apps.authapi.oauth.build_allauth_authorize_url')
    def test_discord_authorize_uses_allauth_bridge(self, mocked):
        mocked.return_value = ('https://discord.com/oauth2/authorize?state=abc', None)
        request = self.factory.get('/api/v1/authorize')
        url, pkce = build_authorize_url(
            'discord',
            redirect_uri='https://auth.example.com/api/v1/oauth/callback',
            state='signed-state',
            request=request,
            company_id=self.company.id,
            company_oauth_client_id=self.discord_client.id,
        )
        self.assertIsNone(pkce)
        self.assertIn('discord.com', url)
        self.assertEqual(mocked.call_count, 1)

    @patch('apps.authapi.oauth.exchange_allauth_code')
    def test_openid_connect_exchange_uses_allauth(self, mocked):
        sociallogin = MagicMock()
        sociallogin.account.uid = 'kc-sub'
        sociallogin.account.extra_data = {'sub': 'kc-sub', 'email': 'user@example.com', 'email_verified': True}
        sociallogin.user.email = 'user@example.com'
        sociallogin.user.get_full_name.return_value = 'User'
        mocked.return_value = (sociallogin, {'access_token': 'at', 'id_token': 'eyJ.test'})
        request = self.factory.get('/api/v1/oauth/callback', {'code': 'the-code'})
        bundle = exchange_code_for_token(
            'keycloak',
            code='the-code',
            redirect_uri='https://auth.example.com/api/v1/oauth/callback',
            request=request,
            company_id=self.company.id,
            company_oauth_client_id=self.oidc_client.id,
        )
        self.assertEqual(bundle.access_token, 'at')
        self.assertEqual(mocked.call_count, 1)

    def test_discord_unverified_email_does_not_link_existing_user(self):
        victim = User.objects.create_user(username='v', email='victim@example.com', password='x')
        profile, _err = extract_oauth_profile(
            'discord',
            {'id': '123', 'email': 'victim@example.com', 'email_verified': False},
            'token',
        )
        assert profile is not None
        user, created, err = resolve_oauth_user(provider='discord', profile=profile)
        self.assertIsNone(user)
        self.assertIn('verify', (err or '').lower())

    def test_oidc_verified_email_links(self):
        victim = User.objects.create_user(username='v2', email='oidc@example.com', password='x')
        profile, _err = extract_oauth_profile(
            'keycloak',
            {'sub': 'abc', 'email': 'oidc@example.com', 'email_verified': True},
            'token',
            id_token_claims={'email_verified': True},
        )
        assert profile is not None
        user, _created, err = resolve_oauth_user(provider='keycloak', profile=profile)
        self.assertIsNone(err)
        self.assertEqual(user.pk, victim.pk)
