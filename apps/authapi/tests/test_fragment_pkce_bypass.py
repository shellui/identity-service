"""Tokens are never sent in the URL fragment, so fragment delivery cannot skip PKCE (#99)."""

import re

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.checks import oauth_fragment_delivery_ignored
from apps.authapi.tests.pkce_constants import CHALLENGE, PKCE_BODY
from apps.authapi.views import _build_oauth_login_redirect
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthRedirect

User = get_user_model()

PAYLOAD = {'access_token': 'secret-access', 'refresh_token': 'secret-refresh', 'expires_at': 1}


class FragmentRedirectBuilderTests(TestCase):
    """Every sign-in path (OAuth providers, SAML, magic link, confirm, callback) ends here."""

    def setUp(self):
        self.company = Company.objects.create(name='Frag Co', slug='frag-co')
        self.user = User.objects.create_user(username='frag', email='frag@example.com', password='x')

    def _build(self, redirect_to, *, challenge=None, delivery='fragment'):
        return _build_oauth_login_redirect(
            user=self.user,
            company=self.company,
            redirect_to=redirect_to,
            payload=dict(PAYLOAD),
            provider='github',
            token_delivery=delivery,
            code_challenge=challenge,
        )

    def _assert_no_tokens(self, location):
        self.assertNotIn('#', location)
        self.assertNotIn('secret-access', location)
        self.assertNotIn('secret-refresh', location)
        self.assertNotIn('access_token', location)

    def test_https_fragment_without_challenge_is_refused(self):
        location = self._build('https://shell.example.com/login/callback')
        self._assert_no_tokens(location)
        self.assertIn('pkce_required', location)
        self.assertNotIn('shellui_auth_code=', location)

    def test_https_fragment_with_challenge_uses_code(self):
        location = self._build('https://shell.example.com/login/callback', challenge=CHALLENGE)
        self._assert_no_tokens(location)
        self.assertIn('shellui_auth_code=', location)

    def test_custom_scheme_fragment_without_challenge_is_refused(self):
        location = self._build('myapp://auth/callback')
        self._assert_no_tokens(location)
        self.assertIn('pkce_required', location)

    def test_unknown_delivery_without_challenge_is_refused(self):
        location = self._build('https://shell.example.com/login/callback', delivery='')
        self._assert_no_tokens(location)
        self.assertIn('pkce_required', location)


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
    MAGIC_LINK_ENABLED=True,
    OAUTH_TOKEN_DELIVERY='fragment',
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
)
class MagicLinkFragmentTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.company = Company.objects.create(name='Magic Frag', slug='magic-frag')
        CompanyOAuthRedirect.objects.create(company=self.company, base_url='https://app.example.com', is_active=True)
        self.redirect_to = 'https://app.example.com/login/callback'
        user = User.objects.create_user(username='m', email='m@example.com', password='x')
        set_company_access(self.company, user, enabled=True)

    def test_browser_verify_never_puts_tokens_in_fragment(self):
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                '/api/v1/magic-link/request',
                {'company_id': self.company.id, 'email': 'm@example.com', 'redirect_to': self.redirect_to, **PKCE_BODY},
                format='json',
            )
        self.assertEqual(response.status_code, 200)
        raw = re.search(r'token=([^&\s]+)', mail.outbox[0].body).group(1)
        verified = self.client.post(
            '/api/v1/magic-link/verify?token_delivery=fragment',
            {'token': raw, 'company_id': self.company.id},
        )
        location = verified.get('Location') or verified.content.decode()
        self.assertNotIn('#access_token', location)
        self.assertNotIn('access_token=', location)
        self.assertIn('shellui_auth_code=', location)


class FragmentDeliveryCheckTests(SimpleTestCase):
    @override_settings(OAUTH_TOKEN_DELIVERY='fragment')
    def test_warns_when_fragment_configured(self):
        ids = [m.id for m in oauth_fragment_delivery_ignored(None)]
        self.assertEqual(ids, ['authapi.W001'])

    @override_settings(OAUTH_TOKEN_DELIVERY='code')
    def test_silent_with_code(self):
        self.assertEqual(oauth_fragment_delivery_ignored(None), [])
