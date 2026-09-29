from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.db import IntegrityError
from django.test import TestCase, override_settings
from rest_framework.test import APIClient, APITestCase

from dataclasses import replace
from unittest.mock import patch

from apps.authapi.provider_registry import get_provider_catalog
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthClient
from apps.authapi.tests.oauth_real_provider_harness import PUBLIC_HOST
from apps.companies.oauth_client_uniqueness import compute_oauth_client_dedupe_key

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
)
class OAuthCompanyAppUniquenessApiTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Dedupe Co', slug='dedupe-co')
        self.owner = User.objects.create_user(username='dedupe-owner', email='dedupe@example.com', password='x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.client.force_authenticate(user=self.owner)
        self.site = Site.objects.get_current()

    def _create_github(self, *, suffix: str = 'a') -> SocialApp:
        app = SocialApp.objects.create(
            provider='github',
            name=f'github-{suffix}',
            client_id=f'cid-{suffix}',
            secret='secret',
            settings={'catalog_slug': 'github', 'created_by_company_id': self.company.id},
        )
        app.sites.add(self.site)
        CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        return app

    def test_catalog_exposes_multiple_allowed(self):
        catalog = get_provider_catalog()
        github = catalog.by_slug()['github']
        keycloak = catalog.by_slug()['keycloak']
        self.assertFalse(github.multiple_allowed)
        self.assertTrue(keycloak.multiple_allowed)

    def test_create_duplicate_named_provider_returns_409(self):
        existing = self._create_github()
        response = self.client.post(
            f'/api/v1/oauth-social-apps?company_id={self.company.id}',
            {
                'docs_slug': 'github',
                'client_id': 'cid-2',
                'client_secret': 'secret-2',
            },
            format='json',
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error_code'], 'oauth_app_duplicate_provider')
        self.assertEqual(response.data['social_app_id'], existing.id)
        self.assertNotIn('error', response.data)

    def _catalog_with_keycloak_supported(self):
        catalog = get_provider_catalog()
        patched = []
        for entry in catalog.providers:
            if entry.docs_slug == 'keycloak':
                patched.append(replace(entry, supported=True, unsupported_reason=None))
            else:
                patched.append(entry)
        return replace(catalog, providers=tuple(patched))

    def test_two_keycloak_instances_allowed(self):
        entry = get_provider_catalog().by_slug()['keycloak']
        for idx, slug_path in enumerate(('keycloak-a', 'keycloak-b'), start=1):
            server_url = f'{PUBLIC_HOST}/{slug_path}/.well-known/openid-configuration'
            with patch(
                'apps.authapi.oauth.get_provider_catalog',
                return_value=self._catalog_with_keycloak_supported(),
            ):
                response = self.client.post(
                    f'/api/v1/oauth-social-apps?company_id={self.company.id}',
                    {
                        'docs_slug': 'keycloak',
                        'client_id': f'cid-{idx}',
                        'client_secret': 'secret',
                        'extra_settings': {
                            'server_url': server_url,
                            'provider_id': f'tenant-{idx}',
                        },
                    },
                    format='json',
                )
            self.assertEqual(response.status_code, 201, response.data)

    def test_duplicate_keycloak_instance_returns_409(self):
        server_url = f'{PUBLIC_HOST}/same-kc/.well-known/openid-configuration'
        with patch(
            'apps.authapi.oauth.get_provider_catalog',
            return_value=self._catalog_with_keycloak_supported(),
        ):
            first = self.client.post(
                f'/api/v1/oauth-social-apps?company_id={self.company.id}',
                {
                    'docs_slug': 'keycloak',
                    'client_id': 'cid-1',
                    'client_secret': 'secret',
                    'extra_settings': {
                        'server_url': server_url,
                        'provider_id': 'tenant-a',
                    },
                },
                format='json',
            )
            self.assertEqual(first.status_code, 201, first.data)
            response = self.client.post(
                f'/api/v1/oauth-social-apps?company_id={self.company.id}',
                {
                    'docs_slug': 'keycloak',
                    'client_id': 'cid-2',
                    'client_secret': 'secret-2',
                    'extra_settings': {
                        'server_url': server_url,
                        'provider_id': 'tenant-a',
                    },
                },
                format='json',
            )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error_code'], 'oauth_app_duplicate_provider')


class OAuthCompanyAppUniquenessDbTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='DB Co', slug='db-co')

    def test_named_provider_dedupe_key_is_catalog_slug(self):
        app = SocialApp.objects.create(
            provider='google',
            name='google-1',
            client_id='g1',
            secret='s',
            settings={'catalog_slug': 'google'},
        )
        self.assertEqual(compute_oauth_client_dedupe_key(app), 'google')

    def test_db_rejects_duplicate_named_provider_mapping(self):
        app_a = SocialApp.objects.create(
            provider='google',
            name='google-a',
            client_id='g1',
            secret='s',
            settings={'catalog_slug': 'google'},
        )
        CompanyOAuthClient.objects.create(company=self.company, social_app=app_a, is_active=True)
        app_b = SocialApp.objects.create(
            provider='google',
            name='google-b',
            client_id='g2',
            secret='s',
            settings={'catalog_slug': 'google'},
        )
        with self.assertRaises(IntegrityError):
            CompanyOAuthClient.objects.create(company=self.company, social_app=app_b, is_active=True)
