"""Custom-scheme desktop redirects: one company scheme list and S256 PKCE."""

from __future__ import annotations

import hashlib
import html
import re
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.core import mail
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.authapi.models import MagicLinkToken, OAuthSessionDeliveryCode
from apps.authapi.oauth import OAuthTokenBundle
from apps.authapi.oauth_session_code import create_oauth_session_delivery_code
from apps.authapi.oauth_state import OAUTH_STATE_NONCE_COOKIE, build_oauth_state, parse_oauth_state
from apps.authapi.saml.request_id import SAML_REQUEST_ID_PREFIX
from apps.authapi.saml.views import SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY
from apps.authapi.tests.saml_test_crypto import generate_test_idp_credentials
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect

User = get_user_model()

# RFC 7636 appendix B.
VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
DESKTOP = 'shellui-playground://callback'
WEB = 'https://shell.example.com/login/callback'


def _href_by_id(page: str, element_id: str) -> str:
    match = re.search(rf'id="{element_id}"[^>]*href="([^"]+)"', page)
    assert match, page
    return html.unescape(match.group(1))


def _return_href(page: str) -> str:
    return _href_by_id(page, 'return-to-app')


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
    AUTH_RATE_LIMIT_ENABLED=False,
    OAUTH_TOKEN_DELIVERY='code',
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    MAGIC_LINK_ENABLED=True,
    JWT_ISSUER='https://auth.example.com',
)
class DesktopRedirectApiTests(TestCase):
    def setUp(self):
        cache.clear()
        mail.outbox.clear()
        self.client = APIClient()
        self.company = Company.objects.create(
            name='Desktop Co',
            slug='desktop-co',
            desktop_redirect_schemes=['shellui-playground'],
        )
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
        self.owner = User.objects.create_user(username='owner', email='owner@example.com', password='x')
        self.member = User.objects.create_user(username='member', email='member@example.com', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.member, enabled=True)
        self.company.owners.add(self.owner)
        self.company.members.add(self.owner, self.member)

    def _oauth_callback(self, state: str):
        payload, err = parse_oauth_state(state)
        self.assertIsNone(err)
        assert payload is not None
        self.client.cookies[OAUTH_STATE_NONCE_COOKIE] = payload['nonce']
        return self.client.get('/api/v1/oauth/callback', {'code': 'auth-code', 'state': state})

    def _confirm_token(self, callback) -> str:
        for line in callback.content.decode('utf-8').splitlines():
            if 'name="confirm_token"' in line:
                start = line.find('value="') + len('value="')
                end = line.find('"', start)
                return line[start:end]
        self.fail('confirm token missing')

    def _patch_schemes(self, user, schemes):
        self.client.force_authenticate(user=user)
        return self.client.patch(
            f'/api/v1/companies/{self.company.id}/',
            {'desktop_redirect_schemes': schemes},
            format='json',
        )

    def test_owner_and_staff_can_register_and_clear_schemes(self):
        rejected = self._patch_schemes(self.owner, ['Com.Shellui.App'])
        self.assertEqual(rejected.status_code, 400, rejected.data)
        for scheme in ('http', 'https', 'javascript', 'data', 'file', 'vbscript', 'about', 'blob', 'web+shellui'):
            response = self._patch_schemes(self.owner, [scheme])
            self.assertEqual(response.status_code, 400, scheme)
        updated = self._patch_schemes(self.owner, ['com.shellui.app', 'com.shellui.app'])
        self.assertEqual(updated.status_code, 200, updated.data)
        self.assertEqual(updated.data['desktop_redirect_schemes'], ['com.shellui.app'])
        self.company.refresh_from_db()
        self.assertEqual(self.company.desktop_redirect_schemes, ['com.shellui.app'])
        staff = User.objects.create_user(
            username='staff',
            email='staff@example.com',
            password='x',
            is_staff=True,
        )
        set_company_access(self.company, staff, enabled=True)
        self.company.members.add(staff)
        staff_updated = self._patch_schemes(staff, ['shellui-playground'])
        self.assertEqual(staff_updated.status_code, 200, staff_updated.data)
        self.assertEqual(staff_updated.data['desktop_redirect_schemes'], ['shellui-playground'])
        cleared = self._patch_schemes(self.owner, [])
        self.assertEqual(cleared.status_code, 200, cleared.data)
        self.assertEqual(cleared.data['desktop_redirect_schemes'], [])

    def test_member_cannot_edit_schemes(self):
        response = self._patch_schemes(self.member, ['com.shellui.other'])
        self.assertIn(response.status_code, (401, 403))
        self.company.refresh_from_db()
        self.assertEqual(self.company.desktop_redirect_schemes, ['shellui-playground'])

    def _patch_dev_flag(self, user, allowed: bool):
        self.client.force_authenticate(user=user)
        return self.client.patch(
            f'/api/v1/companies/{self.company.id}/',
            {'allow_desktop_dev_scheme': allowed},
            format='json',
        )

    def test_member_can_read_desktop_dev_flag_but_cannot_change_it(self):
        self.client.force_authenticate(user=self.member)
        read = self.client.get(f'/api/v1/companies/{self.company.id}/')
        self.assertEqual(read.status_code, 200, read.data)
        self.assertIs(read.data['allow_desktop_dev_scheme'], False)
        denied = self._patch_dev_flag(self.member, True)
        self.assertEqual(denied.status_code, 403)
        self.company.refresh_from_db()
        self.assertFalse(self.company.allow_desktop_dev_scheme)

    def test_owner_and_staff_can_toggle_desktop_dev_flag(self):
        updated = self._patch_dev_flag(self.owner, True)
        self.assertEqual(updated.status_code, 200, updated.data)
        self.assertIs(updated.data['allow_desktop_dev_scheme'], True)
        self.company.refresh_from_db()
        self.assertTrue(self.company.allow_desktop_dev_scheme)

        staff = User.objects.create_user(
            username='dev-flag-staff',
            email='dev-flag-staff@example.com',
            password='x',
            is_staff=True,
        )
        set_company_access(self.company, staff, enabled=True)
        self.company.members.add(staff)
        staff_updated = self._patch_dev_flag(staff, False)
        self.assertEqual(staff_updated.status_code, 200, staff_updated.data)
        self.assertIs(staff_updated.data['allow_desktop_dev_scheme'], False)
        self.company.refresh_from_db()
        self.assertFalse(self.company.allow_desktop_dev_scheme)

        superuser = User.objects.create_user(
            username='dev-flag-root',
            email='dev-flag-root@example.com',
            password='x',
            is_staff=False,
            is_superuser=True,
        )
        set_company_access(self.company, superuser, enabled=True)
        self.company.members.add(superuser)
        super_updated = self._patch_dev_flag(superuser, True)
        self.assertEqual(super_updated.status_code, 200, super_updated.data)
        self.assertIs(super_updated.data['allow_desktop_dev_scheme'], True)
        self.company.refresh_from_db()
        self.assertTrue(self.company.allow_desktop_dev_scheme)

    def test_one_scheme_serves_social_and_magic_link(self):
        params = {
            'company_id': self.company.id,
            'code_challenge': CHALLENGE,
            'code_challenge_method': 'S256',
        }
        social = self.client.get(
            '/api/v1/authorize',
            {**params, 'provider': 'github', 'redirect_to': DESKTOP},
        )
        self.assertEqual(social.status_code, 302, social.content)
        with self.captureOnCommitCallbacks(execute=True):
            magic = self.client.post(
                '/api/v1/magic-link/request',
                {
                    'company_id': self.company.id,
                    'email': 'member@example.com',
                    'redirect_to': DESKTOP,
                    'code_challenge': CHALLENGE,
                    'code_challenge_method': 'S256',
                },
                format='json',
            )
        self.assertEqual(magic.status_code, 200, getattr(magic, 'data', None))
        self.assertEqual(len(mail.outbox), 1)

        unknown = self.client.get(
            '/api/v1/authorize',
            {**params, 'provider': 'github', 'redirect_to': 'com.other.app://callback'},
        )
        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(unknown.json()['error_code'], 'unregistered_scheme')
        unknown_magic = self.client.post(
            '/api/v1/magic-link/request',
            {
                'company_id': self.company.id,
                'email': 'member@example.com',
                'redirect_to': 'com.other.app://callback',
                'code_challenge': CHALLENGE,
                'code_challenge_method': 'S256',
            },
            format='json',
        )
        self.assertEqual(unknown_magic.status_code, 400)
        self.assertIn('not registered', unknown_magic.data['error'])

        self.company.desktop_redirect_schemes = []
        self.company.save(update_fields=['desktop_redirect_schemes'])
        off = self.client.get(
            '/api/v1/authorize',
            {**params, 'provider': 'github', 'redirect_to': DESKTOP},
        )
        self.assertEqual(off.status_code, 400)
        self.assertEqual(off.json()['error_code'], 'unregistered_scheme')
        off_magic = self.client.post(
            '/api/v1/magic-link/request',
            {
                'company_id': self.company.id,
                'email': 'member@example.com',
                'redirect_to': DESKTOP,
                'code_challenge': CHALLENGE,
                'code_challenge_method': 'S256',
            },
            format='json',
        )
        self.assertEqual(off_magic.status_code, 400)
        self.assertIn('not registered', off_magic.data['error'])

    def test_authorize_requires_s256_pkce_for_desktop_only(self):
        missing = self.client.get(
            '/api/v1/authorize',
            {'provider': 'github', 'company_id': self.company.id, 'redirect_to': DESKTOP},
        )
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.json()['error_code'], 'pkce_required')

        plain = self.client.get(
            '/api/v1/authorize',
            {
                'provider': 'github',
                'company_id': self.company.id,
                'redirect_to': DESKTOP,
                'code_challenge': CHALLENGE,
                'code_challenge_method': 'plain',
            },
        )
        self.assertEqual(plain.status_code, 400)
        self.assertEqual(plain.json()['error_code'], 'invalid_code_challenge_method')

        web = self.client.get(
            '/api/v1/authorize',
            {'provider': 'github', 'company_id': self.company.id, 'redirect_to': WEB},
        )
        self.assertEqual(web.status_code, 302)

        desktop = self.client.get(
            '/api/v1/authorize',
            {
                'provider': 'github',
                'company_id': self.company.id,
                'redirect_to': DESKTOP,
                'code_challenge': CHALLENGE,
                'code_challenge_method': 'S256',
            },
        )
        self.assertEqual(desktop.status_code, 302)
        location = desktop['Location']
        self.assertNotIn(VERIFIER, location)
        state = parse_qs(urlsplit(location).query)['state'][0]
        payload, err = parse_oauth_state(state)
        self.assertIsNone(err)
        assert payload is not None
        self.assertEqual(payload['code_challenge'], CHALLENGE)
        self.assertNotIn('code_verifier', payload)

    def test_method_picker_keeps_pkce_on_provider_links(self):
        response = self.client.get(
            '/api/v1/authorize',
            {
                'company_id': self.company.id,
                'redirect_to': DESKTOP,
                'code_challenge': CHALLENGE,
                'code_challenge_method': 'S256',
            },
        )
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('code_challenge=', content)
        self.assertIn(CHALLENGE, content)
        self.assertIn('code_challenge_method=S256', content)
        self.assertNotIn(VERIFIER, content)

    def test_scheme_match_accepts_other_paths_and_rejects_other_schemes(self):
        for redirect_to in (
            'shellui-playground://callback/extra',
            'shellui-playground://other',
        ):
            response = self.client.get(
                '/api/v1/authorize',
                {
                    'provider': 'github',
                    'company_id': self.company.id,
                    'redirect_to': redirect_to,
                    'code_challenge': CHALLENGE,
                    'code_challenge_method': 'S256',
                },
            )
            self.assertEqual(response.status_code, 302, redirect_to)
        for redirect_to in (
            'javascript:alert(1)',
            'shellui-playground://user@callback',
            'com.other.app://callback',
        ):
            response = self.client.get(
                '/api/v1/authorize',
                {
                    'provider': 'github',
                    'company_id': self.company.id,
                    'redirect_to': redirect_to,
                    'code_challenge': CHALLENGE,
                    'code_challenge_method': 'S256',
                },
            )
            self.assertEqual(response.status_code, 400, redirect_to)
        fragment = self.client.get(
            '/api/v1/authorize',
            {
                'provider': 'github',
                'company_id': self.company.id,
                'redirect_to': 'shellui-playground://callback#x',
                'code_challenge': CHALLENGE,
                'code_challenge_method': 'S256',
            },
        )
        self.assertEqual(fragment.status_code, 400)
        self.assertIn('fragment', fragment.json()['error'])

    @patch(
        'apps.authapi.oauth_user._fetch_github_verified_primary_email',
        return_value=('member@example.com', True),
    )
    @patch(
        'apps.authapi.views.exchange_code_for_token',
        return_value=OAuthTokenBundle(access_token='provider-access'),
    )
    @patch(
        'apps.authapi.views.fetch_provider_userinfo',
        return_value={'id': 1, 'login': 'member', 'email': 'member@example.com', 'name': 'Member'},
    )
    def test_callback_returns_to_the_app_and_session_checks_pkce(self, _userinfo, _exchange, _gh):
        state, _nonce = build_oauth_state(
            provider='github',
            redirect_to=DESKTOP,
            company_id=self.company.id,
            company_oauth_client_id=self.oauth_client.id,
            code_challenge=CHALLENGE,
        )
        callback = self._oauth_callback(state)
        self.assertEqual(callback.status_code, 200)
        confirmed = self.client.post(
            '/api/v1/oauth/confirm',
            {'confirm_token': self._confirm_token(callback)},
        )
        self.assertEqual(confirmed.status_code, 200)
        page = confirmed.content.decode()
        self.assertIn('data-desktop-return="success"', page)
        self.assertIn('Return to the app', page)
        href = _return_href(page)
        self.assertTrue(href.startswith(DESKTOP + '?'))
        self.assertIn('shellui_auth_code=', href)
        self.assertNotIn('access_token=', href)
        self.assertNotIn(VERIFIER, href)
        auth_code = parse_qs(urlsplit(href).query)['shellui_auth_code'][0]
        row = OAuthSessionDeliveryCode.objects.get(code=auth_code)
        self.assertEqual(row.code_challenge, CHALLENGE)
        self.assertNotIn('code_verifier', row.token_payload)
        self.assertNotIn('code_challenge', row.token_payload)

        missing = self.client.post(
            '/api/v1/oauth/session',
            {'auth_code': auth_code, 'redirect_to': DESKTOP},
            format='json',
            HTTP_ORIGIN='tauri://localhost',
        )
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.data['error_code'], 'pkce_required')
        row.refresh_from_db()
        self.assertIsNone(row.redeemed_at)

        wrong = self.client.post(
            '/api/v1/oauth/session',
            {
                'auth_code': auth_code,
                'redirect_to': DESKTOP,
                'code_verifier': 'a' * 43,
            },
            format='json',
        )
        self.assertEqual(wrong.status_code, 400)
        self.assertEqual(wrong.data['error_code'], 'pkce_verification_failed')
        row.refresh_from_db()
        self.assertIsNone(row.redeemed_at)

        session = self.client.post(
            '/api/v1/oauth/session',
            {
                'auth_code': auth_code,
                'redirect_to': DESKTOP,
                'code_verifier': VERIFIER,
            },
            format='json',
            HTTP_ORIGIN='tauri://localhost',
        )
        self.assertEqual(session.status_code, 200, session.data)
        self.assertIn('access_token', session.data)
        self.assertNotIn(VERIFIER, str(session.data))

    @override_settings(OAUTH_TOKEN_DELIVERY='fragment')
    @patch(
        'apps.authapi.oauth_user._fetch_github_verified_primary_email',
        return_value=('member@example.com', True),
    )
    @patch(
        'apps.authapi.views.exchange_code_for_token',
        return_value=OAuthTokenBundle(access_token='provider-access'),
    )
    @patch(
        'apps.authapi.views.fetch_provider_userinfo',
        return_value={'id': 1, 'login': 'member', 'email': 'member@example.com', 'name': 'Member'},
    )
    def test_desktop_ignores_fragment_delivery(self, _userinfo, _exchange, _gh):
        state, _nonce = build_oauth_state(
            provider='github',
            redirect_to=DESKTOP,
            company_id=self.company.id,
            company_oauth_client_id=self.oauth_client.id,
            token_delivery='fragment',
            code_challenge=CHALLENGE,
        )
        callback = self._oauth_callback(state)
        confirmed = self.client.post(
            '/api/v1/oauth/confirm',
            {'confirm_token': self._confirm_token(callback)},
        )
        self.assertEqual(confirmed.status_code, 200)
        href = _return_href(confirmed.content.decode())
        self.assertIn('shellui_auth_code=', href)
        self.assertNotIn('access_token', href)

    def test_web_session_keeps_origin_check_and_does_not_require_pkce(self):
        delivery = create_oauth_session_delivery_code(
            user=self.member,
            company=self.company,
            redirect_to=WEB,
            token_payload={'access_token': 'web-access', 'refresh_token': 'web-refresh'},
        )
        mismatch = self.client.post(
            '/api/v1/oauth/session',
            {'auth_code': delivery.code, 'redirect_to': WEB},
            format='json',
            HTTP_ORIGIN='https://evil.example.com',
        )
        self.assertEqual(mismatch.status_code, 400)
        self.assertIn('Origin', mismatch.data['error'])
        self.assertNotIn('error_code', mismatch.data)
        delivery.refresh_from_db()
        self.assertIsNone(delivery.redeemed_at)

        optional = create_oauth_session_delivery_code(
            user=self.member,
            company=self.company,
            redirect_to=WEB,
            token_payload={'access_token': 'web-access', 'refresh_token': 'web-refresh'},
            code_challenge=CHALLENGE,
        )
        still_checked = self.client.post(
            '/api/v1/oauth/session',
            {
                'auth_code': optional.code,
                'redirect_to': WEB,
                'code_verifier': VERIFIER,
            },
            format='json',
            HTTP_ORIGIN='tauri://localhost',
        )
        self.assertEqual(still_checked.status_code, 400)
        self.assertIn('Origin', still_checked.data['error'])
        optional.refresh_from_db()
        self.assertIsNone(optional.redeemed_at)

        ok = self.client.post(
            '/api/v1/oauth/session',
            {'auth_code': delivery.code, 'redirect_to': WEB},
            format='json',
            HTTP_ORIGIN='https://shell.example.com',
        )
        self.assertEqual(ok.status_code, 200, ok.data)

    def test_desktop_session_without_origin_succeeds_after_pkce(self):
        delivery = create_oauth_session_delivery_code(
            user=self.member,
            company=self.company,
            redirect_to=DESKTOP,
            token_payload={'access_token': 'desk', 'refresh_token': 'desk-r'},
            code_challenge=CHALLENGE,
        )
        response = self.client.post(
            '/api/v1/oauth/session',
            {
                'auth_code': delivery.code,
                'redirect_to': DESKTOP,
                'code_verifier': VERIFIER,
            },
            format='json',
        )
        self.assertEqual(response.status_code, 200, response.data)

    def test_magic_link_browser_return_and_json_verifier(self):
        with self.captureOnCommitCallbacks(execute=True):
            requested = self.client.post(
                '/api/v1/magic-link/request',
                {
                    'company_id': self.company.id,
                    'email': 'member@example.com',
                    'redirect_to': DESKTOP,
                    'code_challenge': CHALLENGE,
                    'code_challenge_method': 'S256',
                },
                format='json',
            )
        self.assertEqual(requested.status_code, 200, getattr(requested, 'data', requested.content))
        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        self.assertNotIn(VERIFIER, body)
        self.assertNotIn(CHALLENGE, body)
        raw = re.search(r'token=([^&\s]+)', body).group(1)
        row = MagicLinkToken.objects.get()
        self.assertEqual(row.code_challenge, CHALLENGE)
        self.assertNotEqual(row.token_hash, hashlib.sha256(VERIFIER.encode()).hexdigest())

        browser = Client()
        opened = browser.get(f'/api/v1/magic-link/verify?token={raw}&company_id={self.company.id}')
        self.assertEqual(opened.status_code, 200)
        consumed = browser.post(
            f'/api/v1/magic-link/verify?company_id={self.company.id}',
            {'token': raw, 'company_id': self.company.id},
        )
        self.assertEqual(consumed.status_code, 200)
        page = consumed.content.decode()
        self.assertIn('Return to the app', page)
        href = _return_href(page)
        self.assertIn('shellui_auth_code=', href)
        self.assertNotIn(VERIFIER, href)

        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            again = self.client.post(
                '/api/v1/magic-link/request',
                {
                    'company_id': self.company.id,
                    'email': 'member@example.com',
                    'redirect_to': DESKTOP,
                    'code_challenge': CHALLENGE,
                    'code_challenge_method': 'S256',
                    'language': 'fr',
                },
                format='json',
            )
        self.assertEqual(again.status_code, 200)
        raw_fr = re.search(r'token=([^&\s]+)', mail.outbox[0].body).group(1)
        french = Client()
        french.get(f'/api/v1/magic-link/verify?token={raw_fr}&company_id={self.company.id}')
        returned = french.post(
            f'/api/v1/magic-link/verify?company_id={self.company.id}',
            {'token': raw_fr, 'company_id': self.company.id},
            HTTP_ACCEPT_LANGUAGE='fr',
        )
        self.assertEqual(returned.status_code, 200)
        french_page = html.unescape(returned.content.decode())
        self.assertIn('lang="fr"', french_page)
        self.assertIn("Revenir à l'application", french_page)
        self.assertIn("Si l'application ne s'est pas ouverte", french_page)

    def test_magic_link_json_requires_verifier_before_redeem(self):
        with self.captureOnCommitCallbacks(execute=True):
            self.client.post(
                '/api/v1/magic-link/request',
                {
                    'company_id': self.company.id,
                    'email': 'member@example.com',
                    'redirect_to': DESKTOP,
                    'code_challenge': CHALLENGE,
                    'code_challenge_method': 'S256',
                },
                format='json',
            )
        raw = re.search(r'token=([^&\s]+)', mail.outbox[0].body).group(1)
        missing = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': raw, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.data['error_code'], 'pkce_required')
        self.assertIsNone(MagicLinkToken.objects.get().consumed_at)
        ok = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': raw, 'company_id': self.company.id, 'code_verifier': VERIFIER},
            format='json',
        )
        self.assertEqual(ok.status_code, 200, ok.data)
        self.assertIn('access_token', ok.data)
        self.assertNotIn(VERIFIER, str(ok.data))

    def test_magic_link_desktop_without_pkce_is_rejected_for_everyone(self):
        response = self.client.post(
            '/api/v1/magic-link/request',
            {
                'company_id': self.company.id,
                'email': 'member@example.com',
                'redirect_to': DESKTOP,
            },
            format='json',
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error_code'], 'pkce_required')
        self.assertEqual(MagicLinkToken.objects.count(), 0)
        self.assertEqual(len(mail.outbox), 0)

    def test_staff_desktop_request_sends_no_link(self):
        User.objects.filter(pk=self.member.pk).update(is_staff=True)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                '/api/v1/magic-link/request',
                {
                    'company_id': self.company.id,
                    'email': 'member@example.com',
                    'redirect_to': DESKTOP,
                    'code_challenge': CHALLENGE,
                    'code_challenge_method': 'S256',
                },
                format='json',
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MagicLinkToken.objects.count(), 0)
        self.assertEqual(len(mail.outbox), 1)
        rendered = mail.outbox[0].body + ''.join(alt[0] for alt in mail.outbox[0].alternatives)
        self.assertNotIn(VERIFIER, rendered)
        self.assertNotIn(CHALLENGE, rendered)
        self.assertNotIn('magic-link/verify', rendered)
        self.assertNotIn(DESKTOP, rendered)

    def test_web_magic_link_still_omits_pkce(self):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                '/api/v1/magic-link/request',
                {
                    'company_id': self.company.id,
                    'email': 'member@example.com',
                    'redirect_to': WEB,
                },
                format='json',
            )
        self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
        raw = re.search(r'token=([^&\s]+)', mail.outbox[0].body).group(1)
        self.assertEqual(MagicLinkToken.objects.get().code_challenge, '')
        consumed = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': raw, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(consumed.status_code, 200, consumed.data)

    def test_invitation_accepts_a_registered_scheme(self):
        self.client.force_authenticate(user=self.owner)
        with self.captureOnCommitCallbacks(execute=True):
            created = self.client.post(
                f'/api/v1/invitations?company_id={self.company.id}',
                {'email': 'ada@example.com', 'language': 'en', 'app_url': DESKTOP},
                format='json',
            )
        self.assertEqual(created.status_code, 201, created.data)
        html_body = mail.outbox[0].alternatives[0][0]
        self.assertIn('If the button does not open the app, copy this link:', html_body)
        self.assertIn(DESKTOP, html_body)
        self.assertNotIn(VERIFIER, html_body)

        other_path = self.client.post(
            f'/api/v1/invitations?company_id={self.company.id}',
            {'email': 'grace@example.com', 'language': 'en', 'app_url': 'shellui-playground://auth/done'},
            format='json',
        )
        self.assertEqual(other_path.status_code, 201, other_path.data)
        other_scheme = self.client.post(
            f'/api/v1/invitations?company_id={self.company.id}',
            {'email': 'june@example.com', 'language': 'en', 'app_url': 'com.other.app://callback'},
            format='json',
        )
        self.assertEqual(other_scheme.status_code, 400)
        self.assertEqual(other_scheme.data['error_code'], 'invalid_app_url')

        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            french = self.client.post(
                f'/api/v1/invitations?company_id={self.company.id}',
                {
                    'email': 'ada.fr@example.com',
                    'language': 'fr',
                    'app_url': DESKTOP,
                },
                format='json',
            )
        self.assertEqual(french.status_code, 201, french.data)
        self.assertIn(
            "Si le bouton n'ouvre pas l'application, copiez ce lien :",
            mail.outbox[0].alternatives[0][0],
        )

    def test_web_invitation_copy_is_unchanged(self):
        self.client.force_authenticate(user=self.owner)
        with self.captureOnCommitCallbacks(execute=True):
            created = self.client.post(
                f'/api/v1/invitations?company_id={self.company.id}',
                {'email': 'ada@example.com', 'language': 'en', 'app_url': 'https://shell.example.com/'},
                format='json',
            )
        self.assertEqual(created.status_code, 201, created.data)
        html_body = mail.outbox[0].alternatives[0][0]
        self.assertIn('If the button does not work, copy this URL into your browser:', html_body)

    @patch('apps.authapi.views.exchange_code_for_token')
    def test_legacy_exchange_requires_presented_pkce_for_desktop(self, exchange):
        response = self.client.post(
            f'/api/v1/oauth/exchange?company_id={self.company.id}',
            {
                'provider': 'github',
                'code': 'provider-code',
                'redirect_uri': DESKTOP,
            },
            format='json',
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error_code'], 'pkce_required')
        self.assertFalse(exchange.called)

        exchange.return_value = OAuthTokenBundle(access_token='provider-access')
        with patch(
            'apps.authapi.views.fetch_provider_userinfo',
            return_value={'id': 1, 'login': 'member', 'email': 'member@example.com', 'name': 'Member'},
        ), patch(
            'apps.authapi.oauth_user._fetch_github_verified_primary_email',
            return_value=('member@example.com', True),
        ):
            allowed = self.client.post(
                f'/api/v1/oauth/exchange?company_id={self.company.id}',
                {
                    'provider': 'github',
                    'code': 'provider-code',
                    'redirect_uri': DESKTOP,
                    'code_challenge': CHALLENGE,
                    'code_challenge_method': 'S256',
                    'code_verifier': VERIFIER,
                },
                format='json',
            )
        self.assertNotEqual(allowed.data.get('error_code'), 'pkce_required')
        self.assertTrue(exchange.called)

    def test_browser_errors_are_html_and_api_clients_stay_json(self):
        browser = Client()
        params = {
            'provider': 'github',
            'company_id': self.company.id,
            'redirect_to': 'javascript:alert(1)',
            'code_challenge': CHALLENGE,
            'code_challenge_method': 'S256',
        }
        page = browser.get('/api/v1/authorize', params, HTTP_ACCEPT='text/html')
        self.assertEqual(page.status_code, 400)
        body = page.content.decode()
        self.assertIn('text/html', page['Content-Type'])
        self.assertIn('data-error-code="invalid_redirect"', body)
        self.assertIn('Go back', body)
        self.assertNotIn('id="back-to-app"', body)
        self.assertNotIn('javascript:', body)
        self.assertNotIn(CHALLENGE, body)

        french = browser.get(
            '/api/v1/authorize',
            params,
            HTTP_ACCEPT='text/html',
            HTTP_ACCEPT_LANGUAGE='fr',
        )
        french_body = html.unescape(french.content.decode())
        self.assertIn('lang="fr"', french_body)
        self.assertIn("La connexion n'a pas abouti", french_body)
        self.assertIn('Retour', french_body)
        self.assertNotIn('javascript:', french_body)

        as_json = self.client.get('/api/v1/authorize', params)
        self.assertEqual(as_json.status_code, 400)
        self.assertEqual(as_json.json()['error'], 'redirect_to must use http or https.')
        self.assertEqual(as_json.json()['error_code'], 'invalid_redirect')
        self.assertNotIn('<html', as_json.content.decode())

        self.company.desktop_redirect_schemes = []
        self.company.save(update_fields=['desktop_redirect_schemes'])
        unregistered = browser.get(
            '/api/v1/authorize',
            {
                'provider': 'github',
                'company_id': self.company.id,
                'redirect_to': DESKTOP,
                'code_challenge': CHALLENGE,
                'code_challenge_method': 'S256',
            },
            HTTP_ACCEPT='text/html',
        )
        unregistered_body = unregistered.content.decode()
        self.assertIn('data-error-code="unregistered_scheme"', unregistered_body)
        self.assertNotIn('id="back-to-app"', unregistered_body)
        self.assertNotIn('shellui-playground://', unregistered_body)
        self.assertIn('id="go-back"', unregistered_body)

        self.company.desktop_redirect_schemes = ['shellui-playground']
        self.company.save(update_fields=['desktop_redirect_schemes'])
        pkce = browser.get(
            '/api/v1/authorize',
            {'provider': 'github', 'company_id': self.company.id, 'redirect_to': DESKTOP},
            HTTP_ACCEPT='text/html',
            HTTP_ACCEPT_LANGUAGE='en',
        )
        pkce_body = pkce.content.decode()
        self.assertIn('data-error-code="pkce_required"', pkce_body)
        self.assertIn('Back to the app', pkce_body)
        href = _href_by_id(pkce_body, 'back-to-app')
        self.assertEqual(href, f'{DESKTOP}?error=pkce_required')
        self.assertNotIn('shellui_auth_code', href)
        self.assertNotIn('token', href)
        self.assertNotIn(CHALLENGE, pkce_body)

    def test_expired_magic_link_page_returns_to_the_registered_scheme(self):
        from datetime import timedelta

        from django.utils import timezone

        from apps.authapi.magic_link import create_magic_link_token

        _row, raw = create_magic_link_token(
            company=self.company,
            email='member@example.com',
            redirect_to=DESKTOP,
            user=self.member,
            code_challenge=CHALLENGE,
        )
        MagicLinkToken.objects.update(expires_at=timezone.now() - timedelta(seconds=5))
        browser = Client()
        response = browser.get(
            f'/api/v1/magic-link/verify?token={raw}&company_id={self.company.id}',
            HTTP_ACCEPT='text/html',
        )
        self.assertEqual(response.status_code, 400)
        body = response.content.decode()
        self.assertIn('data-error-code="magic_link_expired"', body)
        self.assertNotIn(raw, body)
        self.assertEqual(_href_by_id(body, 'back-to-app'), f'{DESKTOP}?error=magic_link_expired')
        french = browser.get(
            f'/api/v1/magic-link/verify?token={raw}&company_id={self.company.id}',
            HTTP_ACCEPT='text/html',
            HTTP_ACCEPT_LANGUAGE='fr',
        )
        self.assertIn("Revenir à l'application", html.unescape(french.content.decode()))
        self.assertNotIn(raw, french.content.decode())

    def test_social_authorize_stores_desktop_challenge(self):
        missing = self.client.get(
            '/api/v1/providers/github/authorize/',
            {'company_id': self.company.id, 'redirect_uri': DESKTOP},
        )
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.data['error_code'], 'pkce_required')
        ok = self.client.get(
            '/api/v1/providers/github/authorize/',
            {
                'company_id': self.company.id,
                'redirect_uri': DESKTOP,
                'code_challenge': CHALLENGE,
                'code_challenge_method': 'S256',
            },
        )
        self.assertEqual(ok.status_code, 200, ok.data)
        self.assertNotIn(VERIFIER, ok.data['authorize_url'])


@override_settings(
    SECRET_KEY='test-secret-saml-desktop',
    DEBUG=True,
    OAUTH_TOKEN_DELIVERY='code',
    ALLOWED_HOSTS=['identity.test.example', 'testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
)
class DesktopSamlLoginTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.site = Site.objects.get_current()
        self.company = Company.objects.create(
            name='SAML Desktop',
            slug='saml-desktop',
            desktop_redirect_schemes=['shellui-playground'],
        )
        self.creds = generate_test_idp_credentials(entity_id='https://idp.test.example/desktop')
        self.app = SocialApp.objects.create(
            provider='saml',
            name='desktop-saml',
            client_id='c1-desktopslug',
            secret='-',
            settings={
                'catalog_slug': 'saml',
                'shellui_company_id': self.company.id,
                'idp': {
                    'entity_id': self.creds.entity_id,
                    'sso_url': 'https://idp.test.example/sso',
                    'x509cert': self.creds.x509cert_one_line,
                },
                'advanced': {'reject_idp_initiated_sso': True},
            },
        )
        self.app.sites.add(self.site)
        CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.app,
            is_active=True,
        )

    def _login(self, **params):
        login_url = reverse('shellui-saml-login', kwargs={'organization_slug': self.app.client_id})
        return self.client.get(
            login_url,
            data={'redirect_to': DESKTOP, 'company_id': str(self.company.id), **params},
            follow=False,
            HTTP_HOST='identity.test.example',
            HTTP_ACCEPT='text/html',
        )

    def _stashed(self) -> dict:
        request_id = self.client.session[SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY]
        digest = hashlib.sha256(str(request_id).encode('utf-8')).hexdigest()
        return cache.get(f'{SAML_REQUEST_ID_PREFIX}{digest}')

    def test_desktop_login_requires_pkce_and_stores_only_the_challenge(self):
        missing = self._login()
        self.assertEqual(missing.status_code, 400)
        page = missing.content.decode()
        self.assertIn('text/html', missing['Content-Type'])
        self.assertIn('data-error-code="pkce_required"', page)
        self.assertIn('Back to the app', page)
        href = _href_by_id(page, 'back-to-app')
        self.assertEqual(href, 'shellui-playground://callback?error=pkce_required')
        self.assertNotIn('shellui_auth_code', page)
        self.assertNotIn(CHALLENGE, href)
        self.assertNotIn(VERIFIER, page)
        as_json = self.client.get(
            reverse('shellui-saml-login', kwargs={'organization_slug': self.app.client_id}),
            data={
                'redirect_to': DESKTOP,
                'company_id': str(self.company.id),
            },
            HTTP_HOST='identity.test.example',
            HTTP_ACCEPT='application/json',
        )
        self.assertEqual(as_json.status_code, 400)
        self.assertEqual(as_json.json()['error_code'], 'pkce_required')

        started = self._login(code_challenge=CHALLENGE, code_challenge_method='S256')
        self.assertEqual(started.status_code, 302)
        payload = self._stashed()
        self.assertEqual(payload['code_challenge'], CHALLENGE)
        self.assertNotIn('code_verifier', payload)
        self.assertNotIn(VERIFIER, started['Location'])
