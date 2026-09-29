from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.test import RequestFactory, TestCase

from apps.authapi.oauth import OAuthTokenBundle
from apps.authapi.provider_registry import get_provider_catalog
from apps.authapi.views import _resolve_oauth_login_user
from apps.companies.models import Company, CompanyOAuthClient

User = get_user_model()


class OidcLoginCollisionTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.company = Company.objects.create(name='OIDC Co', slug='oidc-co')
        self.site = Site.objects.get_current()

    def _oidc_app(self, *, slug: str, provider_id: str, issuer: str) -> SocialApp:
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

        def _login_with(app: SocialApp, issuer: str):
            userinfo = {
                'sub': 'shared-sub',
                'email': f'user-{issuer.split("//", 1)[-1]}@example.com',
            }
            bundle = OAuthTokenBundle(access_token='at', id_token=None)
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
