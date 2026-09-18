from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthClient

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
)
class AuthSettingsTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.company = Company.objects.create(name='Settings Co', slug='settings-co')
        self.app = SocialApp.objects.create(
            provider='github',
            name='GitHub Test',
            client_id='cid',
            secret='csecret',
        )
        CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.app,
            is_active=True,
        )
        self.member = User.objects.create_user(username='member', email='member@example.com', password='x')
        set_company_access(self.company, self.member, enabled=True)
        self.company.members.add(self.member)

    def test_unauthenticated_settings_omits_oauth_client_details(self):
        response = self.client.get(f'/api/v1/settings?company_id={self.company.id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn('oauthProviders', response.data)
        self.assertNotIn('oauthClients', response.data)
        self.assertNotIn('external', response.data)

    def test_authenticated_member_receives_oauth_client_details(self):
        self.client.force_authenticate(
            user=self.member,
            token={'company_id': self.company.id},
        )
        response = self.client.get(f'/api/v1/settings?company_id={self.company.id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn('oauthClients', response.data)
        self.assertEqual(len(response.data['oauthClients']), 1)
