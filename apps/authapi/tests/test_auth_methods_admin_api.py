from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
    MAGIC_LINK_ENABLED=True,
)
class AuthMethodsAdminApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Admin Auth Co', slug='admin-auth-co')
        self.other = Company.objects.create(name='Other Auth Co', slug='other-auth-co')
        self.owner = User.objects.create_user(username='owner', email='owner@example.com', password='x')
        self.member = User.objects.create_user(username='member', email='member@example.com', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.member, enabled=True)
        self.company.owners.add(self.owner)
        self.company.members.add(self.owner, self.member)
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://app.example.com',
            is_active=True,
        )
        self.redirect_to = 'https://app.example.com/login/callback'
        app = SocialApp.objects.create(
            provider='github',
            name='GitHub',
            client_id='cid',
            secret='sec',
        )
        CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)

    def _url(self, path: str, company=None) -> str:
        cid = (company or self.company).id
        sep = '&' if '?' in path else '?'
        return f'{path}{sep}company_id={cid}'

    def _as_owner(self):
        self.client.force_authenticate(user=self.owner)

    def test_get_includes_magic_link_and_oauth(self):
        self._as_owner()
        response = self.client.get(self._url('/api/v1/auth-methods'))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data['enable_magic_link'])
        self.assertTrue(response.data['magic_link_effective'])
        self.assertTrue(response.data['magic_link_globally_enabled'])
        self.assertTrue(response.data['enable_oauth'])
        self.assertEqual(response.data['oauth_providers'], ['github'])
        self.assertIn('magic_link', response.data['methods'])
        self.assertIn('oauth', response.data['methods'])

    def test_member_forbidden(self):
        self.client.force_authenticate(user=self.member)
        for method in ('get', 'patch'):
            if method == 'get':
                response = self.client.get(self._url('/api/v1/auth-methods'))
            else:
                response = self.client.patch(
                    self._url('/api/v1/auth-methods'),
                    {'enable_magic_link': False},
                    format='json',
                )
            self.assertEqual(response.status_code, 403, response.data)

    def test_patch_disables_magic_link_request(self):
        self._as_owner()
        disabled = self.client.patch(
            self._url('/api/v1/auth-methods'),
            {'enable_magic_link': False},
            format='json',
        )
        self.assertEqual(disabled.status_code, 200)
        self.assertFalse(disabled.data['enable_magic_link'])
        self.assertFalse(disabled.data['magic_link_effective'])
        self.assertNotIn('magic_link', disabled.data['methods'])

        request = self.client.post(
            '/api/v1/magic-link/request',
            {
                'company_id': self.company.id,
                'email': 'member@example.com',
                'redirect_to': self.redirect_to,
            },
            format='json',
        )
        self.assertEqual(request.status_code, 403)
        self.assertEqual(request.data['error_code'], 'magic_link_disabled')

        settings_resp = self.client.get(f'/api/v1/settings?company_id={self.company.id}')
        self.assertFalse(settings_resp.data['enable_magic_link'])

    def test_put_re_enables_magic_link(self):
        self._as_owner()
        self.client.patch(
            self._url('/api/v1/auth-methods'),
            {'enable_magic_link': False},
            format='json',
        )
        enabled = self.client.put(
            self._url('/api/v1/auth-methods'),
            {'enable_magic_link': True},
            format='json',
        )
        self.assertEqual(enabled.status_code, 200)
        self.assertTrue(enabled.data['magic_link_effective'])

    @override_settings(MAGIC_LINK_ENABLED=False)
    def test_get_reflects_global_kill_switch(self):
        self._as_owner()
        response = self.client.get(self._url('/api/v1/auth-methods'))
        self.assertTrue(response.data['enable_magic_link'])
        self.assertFalse(response.data['magic_link_globally_enabled'])
        self.assertFalse(response.data['magic_link_effective'])
