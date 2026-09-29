from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework.test import APIClient, APITestCase

from apps.authapi.provider_registry import get_provider_catalog, validate_extra_settings
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthClient

User = get_user_model()


class ProviderRegistryTests(APITestCase):
    def test_catalog_loads_all_entries(self):
        catalog = get_provider_catalog()
        self.assertEqual(len(catalog.providers), 114)
        self.assertEqual(len(catalog.supported_slugs()), 3)

    def test_microsoft_extra_settings_validation(self):
        entry = get_provider_catalog().by_slug()['microsoft']
        normalized, errors = validate_extra_settings(entry, {'tenant': 'contoso.onmicrosoft.com'})
        self.assertEqual(errors, [])
        self.assertEqual(normalized['tenant'], 'contoso.onmicrosoft.com')
        self.assertEqual(normalized['catalog_slug'], 'microsoft')


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
)
class OAuthProviderCatalogApiTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Catalog Co', slug='catalog-co')
        self.owner = User.objects.create_user(username='owner', email='owner@example.com', password='x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)

    def _url(self, path: str) -> str:
        return f'{path}?company_id={self.company.id}'

    def test_catalog_requires_owner_or_staff(self):
        response = self.client.get(self._url('/api/v1/oauth-provider-catalog'))
        self.assertEqual(response.status_code, 401)

    def test_catalog_lists_supported_providers_with_callback(self):
        self.client.force_authenticate(user=self.owner)
        response = self.client.get(self._url('/api/v1/oauth-provider-catalog'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('providers', response.data)
        self.assertIn('callback_url', response.data)
        slugs = {item['docs_slug'] for item in response.data['providers']}
        self.assertIn('github', slugs)
        self.assertNotIn('twitter', slugs)
        github = next(item for item in response.data['providers'] if item['docs_slug'] == 'github')
        self.assertTrue(github['supported'])
        self.assertTrue(response.data['callback_url'].endswith('/api/v1/oauth/callback'))
        self.assertTrue(github['callback_url'].endswith('/api/v1/oauth/callback'))
        self.assertNotIn('allauth_callback_path', github)

    def test_catalog_include_legacy(self):
        self.client.force_authenticate(user=self.owner)
        response = self.client.get(
            self._url('/api/v1/oauth-provider-catalog') + '&include_legacy=1'
        )
        self.assertEqual(response.status_code, 200)
        slugs = {item['docs_slug'] for item in response.data['providers']}
        self.assertIn('twitter', slugs)


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
)
class OAuthSocialAppExtraSettingsTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='OAuth Admin', slug='oauth-admin')
        self.owner = User.objects.create_user(username='oauth-owner', email='owner2@example.com', password='x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.client.force_authenticate(user=self.owner)

    def test_create_rejects_unknown_extra_setting(self):
        response = self.client.post(
            f'/api/v1/oauth-social-apps?company_id={self.company.id}',
            {
                'docs_slug': 'microsoft',
                'client_id': 'cid',
                'client_secret': 'secret',
                'extra_settings': {'not_a_field': 'x'},
            },
            format='json',
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('Unknown extra setting', response.data['error'])

    def test_create_rejects_private_server_url(self):
        entry = get_provider_catalog().by_slug()['keycloak']
        _normalized, errors = validate_extra_settings(
            entry,
            {'server_url': 'http://127.0.0.1/openid'},
        )
        self.assertTrue(errors)

    def test_social_app_list_is_company_scoped_and_redacts_secrets(self):
        app = SocialApp.objects.create(
            provider='apple',
            name='apple-co',
            client_id='aid',
            secret='secret',
            settings={'catalog_slug': 'apple', 'certificate_key': 'PRIVATE'},
        )
        CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        other = Company.objects.create(name='Other', slug='other-co')
        other_app = SocialApp.objects.create(
            provider='google',
            name='other-google',
            client_id='gid',
            secret='gsec',
            settings={'catalog_slug': 'google'},
        )
        CompanyOAuthClient.objects.create(company=other, social_app=other_app, is_active=True)
        response = self.client.get(f'/api/v1/oauth-social-apps?company_id={self.company.id}')
        self.assertEqual(response.status_code, 200)
        ids = {row['id'] for row in response.data['social_apps']}
        self.assertIn(app.id, ids)
        self.assertNotIn(other_app.id, ids)
        apple_row = next(row for row in response.data['social_apps'] if row['id'] == app.id)
        self.assertNotIn('certificate_key', apple_row['extra_settings'])
        self.assertTrue(apple_row['extra_settings'].get('certificate_key_set'))
