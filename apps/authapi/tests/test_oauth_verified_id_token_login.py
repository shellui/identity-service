from django.contrib.auth import get_user_model
from django.test import TestCase

from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site

from apps.authapi.oauth import OAuthTokenBundle
from apps.authapi.oauth_user import extract_oauth_profile
from apps.authapi.provider_registry import get_provider_catalog
from apps.authapi.views import _resolve_oauth_login_user
from apps.companies.models import Company, CompanyOAuthClient

User = get_user_model()


class VerifiedIdTokenLoginPolicyTests(TestCase):
    def test_microsoft_rejects_missing_verified_tid(self):
        entry = get_provider_catalog().by_slug()['microsoft']
        profile, err = extract_oauth_profile(
            'microsoft',
            {'email': 'user@contoso.com', 'mail': 'user@contoso.com'},
            'access',
            tenant='contoso.onmicrosoft.com',
            id_token_claims={},
            catalog_entry=entry,
        )
        self.assertIsNone(profile)
        self.assertIn('verified ID token', err or '')

    def test_microsoft_accepts_matching_tid_from_verified_claims(self):
        entry = get_provider_catalog().by_slug()['microsoft']
        guid = '11111111-1111-1111-1111-111111111111'
        profile, err = extract_oauth_profile(
            'microsoft',
            {'email': 'user@contoso.com', 'mail': 'user@contoso.com'},
            'access',
            tenant=guid,
            id_token_claims={'tid': guid, 'xms_edov': False},
            catalog_entry=entry,
        )
        self.assertIsNone(err)
        self.assertTrue(profile.email_verified_for_link)

    def test_oidc_rejects_unverified_email_claims(self):
        entry = get_provider_catalog().by_slug()['keycloak']
        profile, err = extract_oauth_profile(
            'keycloak',
            {'email': 'user@example.com', 'sub': 'sub-1'},
            'access',
            id_token_claims={
                'email': 'user@example.com',
                'email_verified': True,
            },
            catalog_entry=entry,
        )
        self.assertIsNone(err)
        self.assertIsNotNone(profile)
        self.assertFalse(profile.email_verified_for_link)

    def test_keycloak_does_not_auto_link_even_with_verified_id_token_email(self):
        entry = get_provider_catalog().by_slug()['keycloak']
        profile, err = extract_oauth_profile(
            'keycloak',
            {'email': 'user@example.com', 'sub': 'sub-1'},
            'access',
            id_token_claims={
                'iss': 'https://issuer.example.com',
                'email': 'user@example.com',
                'email_verified': True,
            },
            catalog_entry=entry,
        )
        self.assertIsNone(err)
        assert profile is not None
        self.assertFalse(profile.email_verified_for_link)

    def test_microsoft_login_resolver_uses_verified_tid(self):
        company = Company.objects.create(name='MS Co', slug='ms-co')
        site = Site.objects.get_current()
        app = SocialApp.objects.create(
            provider='microsoft',
            name='MS audit',
            client_id='ms-client',
            secret='ms-secret',
            settings={
                'catalog_slug': 'microsoft',
                'tenant': 'contoso.onmicrosoft.com',
                'created_by_company_id': company.id,
            },
        )
        app.sites.add(site)
        client = CompanyOAuthClient.objects.create(company=company, social_app=app, is_active=True)
        userinfo = {
            'mail': 'user@contoso.com',
            'userPrincipalName': 'user@contoso.com',
        }
        user, created, profile, err, _code = _resolve_oauth_login_user(
            provider='microsoft',
            company=company,
            userinfo=userinfo,
            token_bundle=OAuthTokenBundle(access_token='at', id_token=None),
            company_oauth_client_id=client.id,
        )
        self.assertIsNotNone(err)
        self.assertIsNone(user)
