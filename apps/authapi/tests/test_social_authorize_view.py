from django.contrib.sites.models import Site
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from allauth.socialaccount.models import SocialApp
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect
from django.contrib.auth import get_user_model

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
)
class SocialAuthorizeViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Auth Co', slug='auth-co')
        self.user = User.objects.create_user(username='auth-user', email='auth@example.com', password='x')
        self.company.owners.add(self.user)
        set_company_access(self.company, self.user, enabled=True)
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )
        self.site = Site.objects.get_current()

    def test_apple_authorize_includes_nonce_and_sets_state_cookie(self):
        app = SocialApp.objects.create(
            provider='apple',
            name='apple-api',
            client_id='apple-client',
            secret='sec',
            key='TEAM',
            settings={'catalog_slug': 'apple', 'created_by_company_id': self.company.id},
        )
        app.sites.add(self.site)
        client = CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        response = self.client.get(
            f'/api/v1/providers/apple/authorize/?company_id={self.company.id}'
            f'&company_oauth_client_id={client.id}&redirect_uri=https://shell.example.com/cb',
        )
        self.assertEqual(response.status_code, 200)
        from urllib.parse import parse_qs, urlparse

        url = response.data['authorize_url']
        self.assertIn('nonce=', url)
        from apps.authapi.oauth_state import OAUTH_STATE_NONCE_COOKIE

        self.assertIn(OAUTH_STATE_NONCE_COOKIE, response.cookies)
        nonce = parse_qs(urlparse(url).query).get('nonce', [''])[0]
        self.assertTrue(nonce)
        self.assertEqual(response.cookies[OAUTH_STATE_NONCE_COOKIE].value, nonce)
