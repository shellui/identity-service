"""Server-to-server session exchange, refresh, and logout for the shell host.

The host forwards the shell page origin in ``Origin`` and sends no browser cookies.
PKCE, single use, and the code lifetime stay in place.
"""

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.models import OAuthSessionDeliveryCode
from apps.authapi.oauth_session_code import create_oauth_session_delivery_code
from apps.authapi.refresh_sessions import is_access_jti_denied
from apps.authapi.tests.pkce_constants import CHALLENGE, VERIFIER
from apps.authapi.tokens import ShellUIAccessToken
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthRedirect
from apps.companies.redirect_allowlist import validate_redirect_to_for_company

User = get_user_model()

SHELL_ORIGIN = 'https://app.example.com'
OTHER_ORIGIN = 'https://other.example.com'
REDIRECT_TO = f'{SHELL_ORIGIN}/login/callback?provider=github'


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    DEBUG=False,
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=False,
    OAUTH_TOKEN_DELIVERY='code',
)
class ShellHostSessionTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Host Co', slug='host-co')
        self.user = User.objects.create_user(
            username='host-user',
            email='host@example.com',
            password='secret',
        )
        set_company_access(self.company, self.user, enabled=True)
        self.company.members.add(self.user)
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url=OTHER_ORIGIN,
            is_active=True,
        )
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url=SHELL_ORIGIN,
            is_active=True,
        )

    def _host(self) -> APIClient:
        return APIClient(enforce_csrf_checks=True)

    def _issue_code(self) -> str:
        payload = _issue_shellui_tokens(self.user, company=self.company, oauth_provider='github')
        row = create_oauth_session_delivery_code(
            user=self.user,
            company=self.company,
            redirect_to=REDIRECT_TO,
            token_payload={**payload, 'provider': 'github'},
            code_challenge=CHALLENGE,
        )
        return row.code

    def test_allowlist_gates_the_shell_redirect(self):
        request = RequestFactory().get('/api/v1/authorize')
        denied_company = Company.objects.create(name='Closed Co', slug='closed-co')
        blocked, blocked_err = validate_redirect_to_for_company(
            company=denied_company,
            request=request,
            redirect_to_raw=REDIRECT_TO,
        )
        self.assertIsNone(blocked)
        self.assertIn('not allowed', blocked_err or '')

        allowed, allowed_err = validate_redirect_to_for_company(
            company=self.company,
            request=request,
            redirect_to_raw=REDIRECT_TO,
        )
        self.assertIsNone(allowed_err)
        self.assertEqual(allowed, REDIRECT_TO)

    def test_server_exchange_refresh_and_logout_send_no_cookies(self):
        code = self._issue_code()
        host = self._host()

        wrong_origin = host.post(
            '/api/v1/oauth/session',
            {'auth_code': code, 'redirect_to': REDIRECT_TO, 'code_verifier': VERIFIER},
            format='json',
            HTTP_ORIGIN=OTHER_ORIGIN,
            HTTP_X_FORWARDED_FOR='203.0.113.50',
        )
        self.assertEqual(wrong_origin.status_code, 400, wrong_origin.data)
        self.assertIn('Origin does not match', wrong_origin.data['error'])
        self.assertIsNone(OAuthSessionDeliveryCode.objects.get(code=code).redeemed_at)

        missing_verifier = self._host().post(
            '/api/v1/oauth/session',
            {'auth_code': code, 'redirect_to': REDIRECT_TO},
            format='json',
            HTTP_ORIGIN=SHELL_ORIGIN,
        )
        self.assertEqual(missing_verifier.status_code, 400, missing_verifier.data)
        self.assertEqual(missing_verifier.data['error_code'], 'pkce_required')
        self.assertIsNone(OAuthSessionDeliveryCode.objects.get(code=code).redeemed_at)

        exchanged = self._host().post(
            '/api/v1/oauth/session',
            {'auth_code': code, 'redirect_to': REDIRECT_TO, 'code_verifier': VERIFIER},
            format='json',
            HTTP_ORIGIN=SHELL_ORIGIN,
            HTTP_X_FORWARDED_FOR='203.0.113.50',
        )
        self.assertEqual(exchanged.status_code, 200, exchanged.data)
        self.assertIn('access_token', exchanged.data)
        self.assertIn('refresh_token', exchanged.data)
        self.assertEqual(list(exchanged.cookies.keys()), [])
        self.assertIsNotNone(OAuthSessionDeliveryCode.objects.get(code=code).redeemed_at)

        again = self._host().post(
            '/api/v1/oauth/session',
            {'auth_code': code, 'redirect_to': REDIRECT_TO, 'code_verifier': VERIFIER},
            format='json',
            HTTP_ORIGIN=SHELL_ORIGIN,
        )
        self.assertEqual(again.status_code, 400, again.data)
        self.assertIn('already used', again.data['error'])

        first_refresh = exchanged.data['refresh_token']
        refreshed = self._host().post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': first_refresh},
            format='json',
            HTTP_ORIGIN=SHELL_ORIGIN,
        )
        self.assertEqual(refreshed.status_code, 200, refreshed.data)
        self.assertIn('access_token', refreshed.data)
        self.assertIn('refresh_token', refreshed.data)
        self.assertNotEqual(refreshed.data['refresh_token'], first_refresh)
        self.assertEqual(list(refreshed.cookies.keys()), [])

        access = refreshed.data['access_token']
        current_refresh = refreshed.data['refresh_token']
        logout = self._host().post(
            '/api/v1/logout',
            {'refresh_token': current_refresh},
            format='json',
            HTTP_AUTHORIZATION=f'Bearer {access}',
            HTTP_ORIGIN=SHELL_ORIGIN,
        )
        self.assertEqual(logout.status_code, 200, getattr(logout, 'data', logout.content))
        self.assertEqual(logout.data, {'success': True})

        after_logout = self._host().post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': current_refresh},
            format='json',
            HTTP_ORIGIN=SHELL_ORIGIN,
        )
        self.assertEqual(after_logout.status_code, 401, after_logout.data)
        rotated = self._host().post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': first_refresh},
            format='json',
            HTTP_ORIGIN=SHELL_ORIGIN,
        )
        self.assertEqual(rotated.status_code, 401, rotated.data)
        self.assertTrue(is_access_jti_denied(str(ShellUIAccessToken(access)['jti'])))
