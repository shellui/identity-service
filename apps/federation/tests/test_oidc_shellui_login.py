"""Sign-in page for the ai-service global OpenID client."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import Client, TestCase, override_settings

from apps.federation.models import VerifiedEmail
from apps.federation.parsing import parse_oidc_clients
from apps.federation.provider import client_requires_shellui_account
from apps.federation.session import COOKIE
from apps.federation.tests.test_federation import ISSUER, _CryptoMixin

User = get_user_model()

AI_REDIRECT = 'https://ai.shellui.com/oauth/mcp/signin/complete'
AI_CLIENT = 'ai-global'
AI_SECRET = 'ai-global-secret-value'


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return verifier, challenge


@override_settings(AUTH_RATE_LIMIT_ENABLED=False)
class ShelluiAccountLoginTests(_CryptoMixin, TestCase):
    def setUp(self):
        self.verifier, self.challenge = _pkce()
        self._enable(
            OIDC_CLIENTS=[
                {
                    'client_id': 'region-app',
                    'client_secret': 'region-secret-value',
                    'redirect_uris': ['https://region.example/oauth/upstream-callback'],
                    'backchannel_logout_uri': '',
                },
                {
                    'client_id': AI_CLIENT,
                    'client_secret': AI_SECRET,
                    'redirect_uris': [AI_REDIRECT],
                    'backchannel_logout_uri': '',
                },
            ],
        )
        self.client = Client()

    def _params(self, **extra):
        params = {
            'response_type': 'code',
            'client_id': AI_CLIENT,
            'redirect_uri': AI_REDIRECT,
            'scope': 'openid email',
            'state': 'state-ai',
            'nonce': 'nonce-ai',
            'code_challenge': self.challenge,
            'code_challenge_method': 'S256',
        }
        params.update(extra)
        return params

    def test_login_page_states_shellui_account_required(self):
        response = self.client.get('/oauth/authorize', self._params())
        self.assertEqual(response.status_code, 200, response.content)
        body = response.content.decode()
        self.assertIn('Shellui', body)
        self.assertIn('ai.shellui.com/mcp is for Shellui accounts', body)
        self.assertIn('https://&lt;regional ai&gt;/c/&lt;company_id&gt;/mcp', body)
        self.assertIn('https://docs.shellui.com', body)
        discovery = self.client.get('/.well-known/openid-configuration')
        self.assertEqual(discovery.json()['prompt_values_supported'], ['none', 'login'])

    def test_password_sign_in_issues_a_code_and_staff_are_refused(self):
        user = User.objects.create_user('ada', 'ada@acme.test', 'secret-pass')
        response = self.client.post(
            '/oauth/authorize?' + urlencode(self._params()),
            {'email': 'ada@acme.test', 'password': 'secret-pass', 'account_choice': 'password'},
        )
        self.assertEqual(response.status_code, 302, response.content)
        query = parse_qs(urlsplit(response['Location']).query)
        self.assertIn('code', query)
        self.assertEqual(query['state'], ['state-ai'])
        self.assertIn(COOKIE, response.cookies)
        token = self.client.post(
            '/oauth/token',
            data=json.dumps(
                {
                    'grant_type': 'authorization_code',
                    'code': query['code'][0],
                    'redirect_uri': AI_REDIRECT,
                    'client_id': AI_CLIENT,
                    'client_secret': AI_SECRET,
                    'code_verifier': self.verifier,
                }
            ),
            content_type='application/json',
        )
        self.assertEqual(token.status_code, 200, token.content)
        claims = jwt.decode(
            token.json()['id_token'],
            self.signing.public_pem,
            algorithms=['RS256'],
            audience=AI_CLIENT,
            issuer=ISSUER,
        )
        self.assertEqual(claims['sub'], str(user.pk))
        self.assertIs(claims['email_verified'], True)
        self.assertNotIn('is_staff', claims)

        staff = User.objects.create_user('sam', 'sam@acme.test', 'secret-pass', is_staff=True)
        refused = self.client.post(
            '/oauth/authorize?' + urlencode(self._params(state='state-staff')),
            {'email': 'sam@acme.test', 'password': 'secret-pass', 'account_choice': 'password'},
        )
        self.assertEqual(refused.status_code, 403, refused.content)
        self.assertIn('Staff accounts', refused.content.decode())
        self.assertNotIn('code=', refused.get('Location', ''))
        self.assertTrue(staff.is_staff)

    def test_existing_session_offers_continue_and_another_account(self):
        """ai-global calls authorize with no prompt. A session shows Continue as."""
        user = User.objects.create_user('ada', 'ada@acme.test', 'secret-pass')
        VerifiedEmail.objects.create(user=user, email='ada@acme.test')
        self.client.cookies[COOKIE] = _session_cookie(user)
        page = self.client.get('/oauth/authorize', self._params())
        self.assertEqual(page.status_code, 200, page.content)
        body = page.content.decode()
        self.assertIn('Continue as ada@acme.test', body)
        self.assertIn('Use another account', body)
        self.assertNotIn('interaction_required', body)
        continued = self.client.post(
            '/oauth/authorize?' + urlencode(self._params()),
            {'account_choice': 'continue'},
        )
        self.assertEqual(continued.status_code, 302, continued.content)
        code = parse_qs(urlsplit(continued['Location']).query)['code'][0]
        token = self.client.post(
            '/oauth/token',
            {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': AI_REDIRECT,
                'client_id': AI_CLIENT,
                'client_secret': AI_SECRET,
                'code_verifier': self.verifier,
            },
        )
        self.assertEqual(token.status_code, 200, token.content)
        claims = jwt.decode(
            token.json()['id_token'],
            self.signing.public_pem,
            algorithms=['RS256'],
            audience=AI_CLIENT,
            issuer=ISSUER,
        )
        self.assertEqual(claims['sub'], str(user.pk))
        self.assertEqual(claims['nonce'], 'nonce-ai')

    def test_staff_session_without_prompt_is_refused(self):
        user = User.objects.create_user('sam', 'sam@acme.test', 'secret-pass', is_staff=True)
        self.client.cookies[COOKIE] = _session_cookie(user)
        page = self.client.get('/oauth/authorize', self._params())
        self.assertEqual(page.status_code, 403, page.content)
        body = page.content.decode()
        self.assertIn('Staff accounts', body)
        self.assertIn('Use another account', body)
        self.assertNotIn('code=', page.get('Location', ''))

    def test_prompt_none_stays_silent_and_refuses_staff(self):
        missing = self.client.get('/oauth/authorize', self._params(prompt='none'))
        self.assertEqual(missing.status_code, 302)
        query = parse_qs(urlsplit(missing['Location']).query)
        self.assertEqual(query['error'], ['login_required'])
        self.assertNotIn('Shellui accounts', missing.content.decode())

        user = User.objects.create_user('sam', 'sam@acme.test', 'secret-pass', is_staff=True)
        self.client.cookies[COOKIE] = _session_cookie(user)
        refused = self.client.get('/oauth/authorize', self._params(prompt='none', state='staff-silent'))
        query = parse_qs(urlsplit(refused['Location']).query)
        self.assertEqual(query['error'], ['access_denied'])
        self.assertIn('Staff', query['error_description'][0])

    def test_prompt_none_without_the_flag_still_accepts_staff(self):
        user = User.objects.create_user('sam', 'sam@acme.test', 'secret-pass', is_staff=True)
        self.client.cookies[COOKIE] = _session_cookie(user)
        response = self.client.get(
            '/oauth/authorize',
            {
                'response_type': 'code',
                'client_id': 'region-app',
                'redirect_uri': 'https://region.example/oauth/upstream-callback',
                'scope': 'openid email',
                'state': 'region-state',
                'nonce': 'region-nonce',
                'prompt': 'none',
            },
        )
        self.assertEqual(response.status_code, 302, response.content)
        self.assertIn('code=', response['Location'])

    def test_missing_csrf_token_is_rejected(self):
        strict = Client(enforce_csrf_checks=True)
        response = strict.post(
            '/oauth/authorize',
            {**self._params(), 'email': 'ada@acme.test', 'password': 'secret-pass', 'account_choice': 'password'},
        )
        self.assertEqual(response.status_code, 403)


def _session_cookie(user) -> str:
    from django.http import HttpResponse

    from apps.federation.session import set_cookie

    response = HttpResponse()
    set_cookie(response, user)
    return response.cookies[COOKIE].value


class TrustedIssuerParseTests(TestCase):
    def test_shellui_account_client_is_the_signin_redirect(self):
        registered = {
            'client_id': 'ai-global-dev',
            'client_secret': 's',
            'redirect_uris': ['http://localhost:8008/oauth/mcp/signin/complete'],
        }
        self.assertTrue(client_requires_shellui_account(registered))
        flagged = {
            'client_id': 'other',
            'redirect_uris': ['https://app.example/cb'],
            'shellui_account_required': True,
        }
        self.assertTrue(client_requires_shellui_account(flagged))
        region = {
            'client_id': 'region',
            'redirect_uris': ['http://localhost:8001/oauth/upstream-callback'],
        }
        self.assertFalse(client_requires_shellui_account(region))

    def test_shellui_account_flag_defaults_off(self):
        clients = parse_oidc_clients(
            '[{"client_id":"ai-global","client_secret":"s","redirect_uris":["https://ai.shellui.com/oauth/mcp/signin/complete"],"shellui_account_required":true}]',
            allow_http=False,
        )
        self.assertTrue(clients[0]['shellui_account_required'])
        plain = parse_oidc_clients(
            '[{"client_id":"region","client_secret":"s","redirect_uris":["https://region.example/oauth/upstream-callback"]}]',
            allow_http=False,
        )
        self.assertFalse(plain[0]['shellui_account_required'])
        with self.assertRaises(ImproperlyConfigured):
            parse_oidc_clients(
                '[{"client_id":"ai-global","client_secret":"s","redirect_uris":["https://ai.shellui.com/cb"],"shellui_account_required":"true"}]',
                allow_http=False,
            )
