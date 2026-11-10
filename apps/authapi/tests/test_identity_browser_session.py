"""Identity browser session: app login cookie, Continue as, logout, dev cookie names."""

from __future__ import annotations

import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.actions.models import EventLog
from apps.agents.models import McpOAuthClient
from apps.authapi.client_pkce import s256_challenge
from apps.authapi.magic_link import create_magic_link_token
from apps.authapi.models import RefreshTokenSession
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthRedirect
from apps.authapi.views import _issue_shellui_tokens
from config.settings import browser_cookie_name

User = get_user_model()

SETTINGS = dict(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    MAGIC_LINK_ENABLED=True,
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
    AI_SERVICE_URL='https://ai.test',
)


@override_settings(**SETTINGS)
class IdentityBrowserSessionTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Acme', slug='acme-browser', enable_magic_link=True)
        CompanyOAuthRedirect.objects.create(company=self.company, base_url='https://app.example.com', is_active=True)
        self.redirect_to = 'https://app.example.com/login/callback'
        self.user = User.objects.create_user(username='ella', email='ella@acme.com', password='member-secret')
        set_company_access(self.company, self.user, enabled=True)
        self.staff = User.objects.create_user(
            username='staff',
            email='staff@acme.com',
            password='staff-secret',
            is_staff=True,
        )
        set_company_access(self.company, self.staff, enabled=True)
        self.outsider = User.objects.create_user(username='out', email='out@other.com', password='unused')
        other = Company.objects.create(name='Other', slug='other-browser')
        set_company_access(other, self.outsider, enabled=True)
        self.other = other

    def _magic_link(self, user=None):
        account = user or self.user
        _row, raw = create_magic_link_token(
            company=self.company,
            email=account.email,
            redirect_to=self.redirect_to,
            user=account,
        )
        return raw

    def test_browser_magic_link_sets_session_cookie_and_json_does_not(self):
        raw = self._magic_link()
        browser = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': raw, 'company_id': str(self.company.id)},
            HTTP_ACCEPT='text/html',
        )
        self.assertEqual(browser.status_code, 302, browser.content)
        self.assertIn('sessionid', browser.cookies)
        self.assertEqual(self.client.session.get('_auth_user_id'), str(self.user.pk))
        self.assertEqual(self.client.session.get('identity_auth_method'), 'magic_link')
        self.assertIn('identity_auth_time', self.client.session)
        self.assertGreater(self.client.session.get_expiry_age(), 6 * 24 * 3600)
        started = EventLog.objects.filter(event_type='identity.auth.login.succeeded').latest('pk')
        self.assertEqual(started.data.get('identity_session'), 'started')
        self.assertEqual(started.data.get('provider'), 'magic_link')

        api = APIClient()
        raw_api = self._magic_link()
        payload = api.post(
            '/api/v1/magic-link/verify',
            {'token': raw_api, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(payload.status_code, 200, payload.content)
        self.assertIn('access_token', payload.data)
        self.assertNotIn('sessionid', payload.cookies)
        self.assertNotIn('_auth_user_id', api.session)

    def test_inactive_user_does_not_get_a_browser_session(self):
        self.user.is_active = False
        self.user.save(update_fields=['is_active'])
        raw = self._magic_link()
        response = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': raw, 'company_id': str(self.company.id)},
        )
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertNotIn('sessionid', getattr(response, 'cookies', {}))

    def test_settings_exposes_logout_url(self):
        response = self.client.get(f'/api/v1/settings?company_id={self.company.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['logout_url'], 'https://identity.test/oauth/logout')

    def test_cli_continue_as_and_use_another_account(self):
        issued = self.client.post(
            '/oauth/cli/device/code',
            {'client_id': 'shellui-cli', 'company_id': self.company.id},
        ).json()
        self.client.force_login(self.user)
        self.client.post('/oauth/cli/device', {'user_code': issued['user_code']})
        page = self.client.get('/oauth/cli/device')
        self.assertContains(page, 'Continue as ella@acme.com')
        self.assertContains(page, 'Use another account')
        french = self.client.get('/oauth/cli/device', HTTP_ACCEPT_LANGUAGE='fr')
        self.assertContains(french, 'Continuer en tant que ella@acme.com')
        self.assertContains(french, 'Utiliser un autre compte')
        switched = self.client.post('/oauth/cli/device', {'account_choice': 'switch'})
        self.assertRedirects(switched, '/oauth/cli/signin', fetch_redirect_response=False)
        self.assertNotIn('_auth_user_id', self.client.session)
        form = self.client.get('/oauth/cli/signin')
        self.assertContains(form, 'name="email"')
        self.assertContains(form, 'Acme')
        self.assertNotContains(form, 'Continue as')
        ended = EventLog.objects.filter(event_type='identity.auth.login.succeeded').latest('pk')
        self.assertEqual(ended.data.get('identity_session'), 'ended')

    def test_staff_cli_step_up_after_12_hours_and_after_magic_link(self):
        issued = self.client.post(
            '/oauth/cli/device/code',
            {'client_id': 'shellui-cli', 'company_id': self.company.id},
        ).json()
        self.client.force_login(self.staff)
        session = self.client.session
        session['identity_auth_time'] = int((timezone.now() - timedelta(hours=13)).timestamp())
        session['identity_auth_method'] = 'password'
        session.set_expiry(7 * 24 * 3600)
        session.save()
        old = self.client.post('/oauth/cli/device', {'user_code': issued['user_code']})
        self.assertRedirects(old, '/oauth/cli/signin', fetch_redirect_response=False)
        page = self.client.get('/oauth/cli/signin')
        self.assertContains(page, 'name="password"')
        self.assertContains(page, 'Sign in again')
        self.assertNotContains(page, 'Continue as')

        fresh = self.client.post(
            '/oauth/cli/device/code',
            {'client_id': 'shellui-cli', 'company_id': self.company.id},
        ).json()
        session = self.client.session
        session['identity_auth_time'] = int(timezone.now().timestamp())
        session['identity_auth_method'] = 'magic_link'
        session.save()
        magic = self.client.post('/oauth/cli/device', {'user_code': fresh['user_code']})
        self.assertRedirects(magic, '/oauth/cli/signin', fetch_redirect_response=False)
        again = self.client.get('/oauth/cli/signin')
        self.assertNotContains(again, 'Continue as')
        self.assertContains(again, 'name="password"')

    def test_staff_password_session_expires_within_12_hours(self):
        issued = self.client.post(
            '/oauth/cli/device/code',
            {'client_id': 'shellui-cli', 'company_id': self.company.id},
        ).json()
        self.client.post('/oauth/cli/device', {'user_code': issued['user_code']})
        signed = self.client.post(
            '/oauth/cli/signin',
            {'email': 'staff@acme.com', 'password': 'staff-secret'},
        )
        self.assertEqual(signed.status_code, 302)
        self.assertLessEqual(self.client.session.get_expiry_age(), 12 * 3600 + 30)
        self.assertEqual(self.client.session.get('identity_auth_method'), 'password')

    def test_mcp_staff_session_is_refused(self):
        client_row = McpOAuthClient.objects.create(
            client_id='mcp-browser',
            client_name='Totally Claude',
            redirect_uris=['https://chatgpt.com/connector'],
        )
        resource = f'https://ai.test/c/{self.company.id}/mcp'
        query = (
            '/oauth/mcp/authorize?response_type=code'
            f'&client_id={client_row.client_id}'
            '&redirect_uri=https://chatgpt.com/connector'
            f'&code_challenge={s256_challenge("b" * 43)}'
            '&code_challenge_method=S256'
            f'&resource={resource}'
        )
        self.client.force_login(self.staff)
        refused = self.client.get(query)
        self.assertEqual(refused.status_code, 403)
        self.assertNotContains(refused, 'Continue as', status_code=403)

    def test_logout_return_to_matches_authorize_allowlist(self):
        tokens = _issue_shellui_tokens(self.user, company=self.company, oauth_provider='magic_link')
        self.assertTrue(RefreshTokenSession.objects.filter(user=self.user, revoked_at__isnull=True).exists())
        self.client.force_login(self.user)
        allowed = self.client.get(
            '/oauth/logout',
            {'return_to': self.redirect_to, 'company_id': self.company.id},
        )
        self.assertEqual(allowed.status_code, 302)
        self.assertEqual(allowed['Location'], self.redirect_to)
        self.assertNotIn('_auth_user_id', self.client.session)
        refreshed = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            data=json.dumps({'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token']}),
            content_type='application/json',
        )
        self.assertEqual(refreshed.status_code, 200, refreshed.content)

        self.client.force_login(self.user)
        rejected = self.client.get(
            '/oauth/logout',
            {'return_to': 'https://evil.example/phish', 'company_id': self.company.id},
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertNotIn('Location', rejected)
        self.assertContains(rejected, 'You are signed out')
        self.assertNotContains(rejected, 'https://evil.example')

        self.client.force_login(self.user)
        missing = self.client.get('/oauth/logout')
        self.assertContains(missing, 'You are signed out')
        posted = self.client.post(
            '/oauth/logout',
            {'return_to': 'https://evil.example/phish', 'company_id': str(self.company.id)},
        )
        self.assertContains(posted, 'You are signed out')
        self.assertNotIn('Location', posted)

        self.client.force_login(self.user)
        other_company = self.client.get(
            '/oauth/logout',
            {'return_to': self.redirect_to, 'company_id': self.other.id},
        )
        self.assertContains(other_company, 'You are signed out')
        self.assertNotIn('Location', other_company)
        scheme = self.client.get(
            '/oauth/logout',
            {'return_to': 'javascript:alert(1)', 'company_id': self.company.id},
        )
        self.assertContains(scheme, 'You are signed out')
        self.assertNotIn('javascript:', scheme.content.decode())


class BrowserCookieNameTests(TestCase):
    def test_http_names_follow_instance_role_and_secure_stays_host_prefix(self):
        self.assertEqual(browser_cookie_name('sessionid', secure=False, role='region'), 'shellui_region_sessionid')
        self.assertEqual(browser_cookie_name('csrftoken', secure=False, role='region'), 'shellui_region_csrftoken')
        self.assertEqual(browser_cookie_name('sessionid', secure=False, role='global'), 'shellui_global_sessionid')
        self.assertEqual(browser_cookie_name('csrftoken', secure=False, role='global'), 'shellui_global_csrftoken')
        self.assertEqual(browser_cookie_name('sessionid', secure=False, role=''), 'sessionid')
        self.assertEqual(browser_cookie_name('sessionid', secure=True, role='region'), '__Host-sessionid')
        self.assertEqual(browser_cookie_name('csrftoken', secure=True, role='global'), '__Host-csrftoken')
