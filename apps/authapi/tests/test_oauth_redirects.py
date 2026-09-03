from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.oauth_state import build_oauth_state, parse_oauth_state
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect

User = get_user_model()


class OAuthStateTests(TestCase):
    def test_roundtrip(self):
        state = build_oauth_state(
            provider='github',
            redirect_to='http://127.0.0.1:9999/callback',
            company_id=42,
            company_oauth_client_id=7,
            client_timezone='Europe/Paris',
        )
        payload, err = parse_oauth_state(state)
        self.assertIsNone(err)
        assert payload is not None
        self.assertEqual(payload['provider'], 'github')
        self.assertEqual(payload['redirect_to'], 'http://127.0.0.1:9999/callback')
        self.assertEqual(payload['company_id'], 42)
        self.assertEqual(payload['company_oauth_client_id'], 7)
        self.assertEqual(payload['client_timezone'], 'Europe/Paris')

    def test_missing_state(self):
        payload, err = parse_oauth_state('')
        self.assertIsNone(payload)
        self.assertIn('Missing', err or '')

    def test_invalid_signature(self):
        payload, err = parse_oauth_state('not-a-valid-signed-state')
        self.assertIsNone(payload)
        self.assertIn('Invalid', err or '')


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
)
class OAuthAuthorizeCallbackTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='OAuth Co', slug='oauth-co')
        self.app = SocialApp.objects.create(
            provider='github',
            name='GitHub Test',
            client_id='cid',
            secret='csecret',
        )
        self.oauth_client = CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.app,
            is_active=True,
        )
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )

    def test_authorize_uses_fixed_callback_and_signed_state(self):
        redirect_to = 'https://shell.example.com/login/callback'
        response = self.client.get(
            '/api/v1/authorize',
            {
                'provider': 'github',
                'company_id': self.company.id,
                'redirect_to': redirect_to,
            },
        )
        self.assertEqual(response.status_code, 302)
        location = response['Location']
        parts = urlsplit(location)
        qs = parse_qs(parts.query)
        self.assertIn('state', qs)
        self.assertIn('redirect_uri', qs)
        redirect_uri = qs['redirect_uri'][0]
        self.assertTrue(redirect_uri.endswith('/api/v1/oauth/callback'))
        self.assertNotIn('?', redirect_uri.split('/api/v1/oauth/callback', 1)[-1] or '')
        payload, err = parse_oauth_state(qs['state'][0])
        self.assertIsNone(err)
        assert payload is not None
        self.assertEqual(payload['redirect_to'], redirect_to)
        self.assertEqual(payload['company_id'], self.company.id)
        self.assertEqual(payload['provider'], 'github')

    def test_authorize_rejects_non_allowlisted_redirect(self):
        response = self.client.get(
            '/api/v1/authorize',
            {
                'provider': 'github',
                'company_id': self.company.id,
                'redirect_to': 'https://evil.example.com/login/callback',
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_authorize_allows_loopback_without_allowlist_row(self):
        CompanyOAuthRedirect.objects.all().delete()
        response = self.client.get(
            '/api/v1/authorize',
            {
                'provider': 'github',
                'company_id': self.company.id,
                'redirect_to': 'http://127.0.0.1:8765/callback',
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_authorize_without_provider_shows_method_picker(self):
        redirect_to = 'http://127.0.0.1:8765/callback'
        response = self.client.get(
            '/api/v1/authorize',
            {
                'company_id': self.company.id,
                'redirect_to': redirect_to,
            },
        )
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('Choose a sign-in method', content)
        self.assertIn('Continue with GitHub', content)
        self.assertIn('provider=github', content)
        self.assertIn('redirect_to=', content)
        self.assertIn('8765', content)

    def test_authorize_without_provider_lists_all_enabled_methods(self):
        google_app = SocialApp.objects.create(
            provider='google',
            name='Google Test',
            client_id='gid',
            secret='gsecret',
        )
        CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=google_app,
            is_active=True,
        )
        redirect_to = 'http://127.0.0.1:8765/callback'
        response = self.client.get(
            '/api/v1/authorize',
            {
                'company_id': self.company.id,
                'redirect_to': redirect_to,
            },
        )
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('Continue with GitHub', content)
        self.assertIn('Continue with Google', content)
        self.assertIn('provider=google', content)
        self.assertIn('provider=github', content)

    def test_authorize_without_provider_rejects_non_allowlisted_redirect(self):
        response = self.client.get(
            '/api/v1/authorize',
            {
                'company_id': self.company.id,
                'redirect_to': 'https://evil.example.com/callback',
            },
        )
        self.assertEqual(response.status_code, 400)

    @patch('apps.authapi.views.exchange_code_for_token', return_value='provider-access')
    @patch(
        'apps.authapi.views.fetch_provider_userinfo',
        return_value={'id': 1, 'login': 'octocat', 'email': 'octocat@example.com', 'name': 'Octo Cat'},
    )
    def test_callback_shows_confirm_then_issues_tokens_on_post(self, _userinfo, exchange):
        redirect_to = 'https://shell.example.com/login/callback'
        state = build_oauth_state(
            provider='github',
            redirect_to=redirect_to,
            company_id=self.company.id,
            company_oauth_client_id=self.oauth_client.id,
        )
        callback = self.client.get(
            '/api/v1/oauth/callback',
            {'code': 'auth-code', 'state': state},
        )
        self.assertEqual(callback.status_code, 200)
        self.assertIn(b'Confirm your account', callback.content)
        self.assertIn(b'octocat@example.com', callback.content)
        self.assertIn(b'Sign-in methods', callback.content)
        self.assertIn(b'GitHub', callback.content)
        confirm_token = None
        for line in callback.content.decode('utf-8').splitlines():
            if 'name="confirm_token"' in line:
                start = line.find('value="') + len('value="')
                end = line.find('"', start)
                confirm_token = line[start:end]
                break
        self.assertTrue(confirm_token)
        confirmed = self.client.post('/api/v1/oauth/confirm', {'confirm_token': confirm_token})
        self.assertEqual(confirmed.status_code, 302)
        location = confirmed['Location']
        self.assertTrue(location.startswith(redirect_to + '#'))
        self.assertIn('access_token=', location)
        self.assertTrue(exchange.called)

    def test_confirm_switch_redirects_to_authorize_with_switch_account(self):
        user = User.objects.create_user(
            username='switcher',
            email='switcher@example.com',
            password='x',
        )
        set_company_access(self.company, user, enabled=True)
        from apps.authapi.oauth_confirm import build_oauth_confirm_token

        token = build_oauth_confirm_token(
            user_id=user.id,
            company_id=self.company.id,
            provider='github',
            redirect_to='http://127.0.0.1:8765/callback',
            company_oauth_client_id=self.oauth_client.id,
        )
        response = self.client.get('/api/v1/oauth/confirm', {'action': 'switch', 'confirm_token': token})
        self.assertEqual(response.status_code, 302)
        location = response['Location']
        self.assertIn('/api/v1/authorize', location)
        self.assertIn('switch_account=1', location)

    def test_callback_invalid_state_returns_400(self):
        response = self.client.get(
            '/api/v1/oauth/callback',
            {'code': 'auth-code', 'state': 'bogus'},
        )
        self.assertEqual(response.status_code, 400)


class OAuthRedirectCrudTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Redirect Co', slug='redirect-co')
        self.owner = User.objects.create_user(username='owner', email='owner@example.com', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.company.members.add(self.owner)
        self.client.force_authenticate(user=self.owner)

    def test_create_list_delete_normalizes_origin(self):
        create = self.client.post(
            f'/api/v1/oauth-redirects?company_id={self.company.id}',
            {'base_url': 'https://App.Example.com/path', 'label': 'Prod shell'},
            format='json',
        )
        self.assertEqual(create.status_code, 201, create.data)
        self.assertEqual(create.data['base_url'], 'https://app.example.com')
        listing = self.client.get(f'/api/v1/oauth-redirects?company_id={self.company.id}')
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.data), 1)
        pk = listing.data[0]['id']
        deleted = self.client.delete(f'/api/v1/oauth-redirects/{pk}?company_id={self.company.id}')
        self.assertEqual(deleted.status_code, 204)
