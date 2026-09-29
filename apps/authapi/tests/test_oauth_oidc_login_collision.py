from unittest import mock

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.test import RequestFactory, TestCase

from apps.authapi.oauth import OAuthTokenBundle
from apps.authapi.oauth_state import build_oauth_state, oauth_state_nonce_cookie_value
from apps.authapi.provider_registry import get_provider_catalog
from apps.authapi.tests.oauth_real_provider_harness import (
    build_profile_for_provider,
    discovery_document_for_slug,
    patch_oauth_http,
    patch_verified_id_token_decode,
)
from apps.authapi.views import _resolve_oauth_login_user
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect

User = get_user_model()


class OidcLoginCollisionTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.company = Company.objects.create(name='OIDC Co', slug='oidc-co')
        self.site = Site.objects.get_current()
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )

    def _oidc_app(self, *, slug: str, provider_id: str, issuer: str) -> SocialApp:
        entry = get_provider_catalog().by_slug()[slug]
        app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id=provider_id,
            name=f'app-{provider_id}',
            client_id=f'client-{provider_id}',
            secret='secret',
            settings={
                'catalog_slug': slug,
                'server_url': f'{issuer}/.well-known/openid-configuration',
                'provider_id': provider_id,
                'created_by_company_id': self.company.id,
            },
        )
        app.sites.add(self.site)
        CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        return app

    def test_same_sub_different_issuers_create_distinct_users_via_login_resolver(self):
        issuer_a = 'https://issuer-a.example.com'
        issuer_b = 'https://issuer-b.example.com'
        app_a = self._oidc_app(slug='keycloak', provider_id='tenant-a', issuer=issuer_a)
        app_b = self._oidc_app(slug='keycloak', provider_id='tenant-b', issuer=issuer_b)
        request = self.factory.get('/api/v1/oauth/callback')
        request.session = {}

        def _login_with(app: SocialApp, issuer: str):
            profile = {'sub': 'shared-sub', 'email': f'user-{issuer}@example.com'}
            discovery = discovery_document_for_slug('keycloak')
            discovery['issuer'] = issuer
            http_session = patch_oauth_http('keycloak', profile, discovery)
            with patch_verified_id_token_decode():
                with mock.patch(
                    'apps.authapi.social_account_adapter.ShellUISocialAccountAdapter.get_requests_session',
                    return_value=http_session,
                ):
                    userinfo = {
                        'sub': 'shared-sub',
                        'email': profile['email'],
                        '_verified_id_token_claims': {
                            'iss': issuer,
                            'sub': 'shared-sub',
                            'email': profile['email'],
                            'email_verified': True,
                        },
                    }
                    bundle = OAuthTokenBundle(access_token='at', id_token='jwt-a')
                    client = CompanyOAuthClient.objects.get(social_app=app)
                    return _resolve_oauth_login_user(
                        provider='keycloak',
                        company=self.company,
                        userinfo=userinfo,
                        token_bundle=bundle,
                        company_oauth_client_id=client.id,
                    )

        user_a, created_a, profile_a, err_a = _login_with(app_a, issuer_a)
        user_b, created_b, profile_b, err_b = _login_with(app_b, issuer_b)
        self.assertIsNone(err_a)
        self.assertIsNone(err_b)
        self.assertTrue(created_a)
        self.assertTrue(created_b)
        self.assertNotEqual(user_a.id, user_b.id)
        self.assertNotEqual(profile_a.social_uid, profile_b.social_uid)
        self.assertNotEqual(profile_a.social_provider, profile_b.social_provider)

    @mock.patch('apps.authapi.views.is_company_access_enabled', return_value=True)
    @mock.patch('apps.authapi.views.should_skip_oauth_confirm', return_value=True)
    @mock.patch('apps.authapi.views.fetch_provider_userinfo')
    @mock.patch('apps.authapi.views.exchange_code_for_token')
    def test_callback_path_uses_verified_oidc_claims(
        self, exchange_mock, userinfo_mock, _skip_confirm, _access
    ):
        from apps.authapi.views import ShellUIOAuthCallbackView

        app = self._oidc_app(slug='linkedin', provider_id='linkedin', issuer='https://linkedin.example.com')
        client = CompanyOAuthClient.objects.get(social_app=app)
        exchange_mock.return_value = OAuthTokenBundle(access_token='at', id_token='jwt')
        userinfo_mock.return_value = {
            'sub': 'li-sub',
            'email': 'user@example.com',
            '_verified_id_token_claims': {
                'iss': 'https://linkedin.example.com',
                'sub': 'li-sub',
                'email': 'user@example.com',
                'email_verified': True,
            },
        }
        redirect_to = 'https://shell.example.com/callback'
        state, nonce = build_oauth_state(
            provider='linkedin',
            redirect_to=redirect_to,
            company_id=self.company.id,
            company_oauth_client_id=client.id,
        )
        request = self.factory.get('/api/v1/oauth/callback', {'code': 'c', 'state': state})
        request.session = {}
        request.COOKIES[oauth_state_nonce_cookie_value(nonce)['key']] = nonce
        response = ShellUIOAuthCallbackView.as_view()(request)
        self.assertEqual(response.status_code, 302, getattr(response, 'content', b''))
        self.assertTrue(User.objects.filter(email='user@example.com').exists())
        exchange_mock.assert_called_once()
        userinfo_mock.assert_called_once()
