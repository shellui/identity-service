"""RFC 8628 device authorization for the Shellui CLI. Separate from the MCP device grant."""

from __future__ import annotations

import json
import re
from datetime import timedelta
from unittest import mock

import jwt
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.actions.models import EventLog
from apps.agents.models import Agent, McpDeviceAuthorization, McpOAuthClient
from apps.agents.oauth_codes import hash_authorization_code
from apps.authapi.login_audit import hash_ip
from apps.authapi.magic_link import build_magic_link_verify_url
from apps.authapi.models import CliDeviceAuthorization, MagicLinkToken, RefreshTokenSession
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

SETTINGS = dict(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AI_SERVICE_URL='https://ai.test',
    MCP_DYNAMIC_CLIENT_REGISTRATION=True,
    AUTH_RATE_LIMIT_ENABLED=False,
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
)
USER_CODE_RE = re.compile(r'^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$')
DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'
CLI_CLIENT = 'shellui-cli'


@override_settings(**SETTINGS)
class CliDeviceFlowTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Acme', slug='acme-cli', enable_magic_link=True)
        self.other = Company.objects.create(name='Other Co', slug='other-cli', enable_magic_link=True)
        self.user = User.objects.create_user(username='ella', email='ella@acme.com', password='member-secret')
        self.company.owners.add(self.user)
        self.company.members.add(self.user)
        set_company_access(self.company, self.user, enabled=True)
        self.outsider = User.objects.create_user(username='out', email='out@other.com', password='unused')
        self.other.owners.add(self.outsider)
        self.other.members.add(self.outsider)
        set_company_access(self.other, self.outsider, enabled=True)
        self.staff = User.objects.create_user(
            username='staff',
            email='staff@acme.com',
            password='staff-secret',
            is_staff=True,
        )
        self.company.owners.add(self.staff)
        self.company.members.add(self.staff)
        set_company_access(self.company, self.staff, enabled=True)
        self.superuser = User.objects.create_user(
            username='root',
            email='root@acme.com',
            password='root-secret',
            is_superuser=True,
        )
        self.company.members.add(self.superuser)
        set_company_access(self.company, self.superuser, enabled=True)
        self.mcp_client = McpOAuthClient.objects.create(
            client_id='hermes-cli-test',
            client_name='Hermes',
            redirect_uris=['http://127.0.0.1/callback'],
        )
        self.resource = f'https://ai.test/c/{self.company.id}/mcp'

    def _issue(self, **overrides):
        as_json = overrides.pop('_json', False)
        extra = {}
        for key in list(overrides):
            if key.startswith('HTTP_') or key == 'REMOTE_ADDR':
                extra[key] = overrides.pop(key)
        payload = {'client_id': CLI_CLIENT, 'company_id': self.company.id}
        payload.update(overrides)
        if as_json:
            return self.client.post(
                '/oauth/cli/device/code',
                data=json.dumps(payload),
                content_type='application/json',
                **extra,
            )
        return self.client.post('/oauth/cli/device/code', payload, **extra)

    def _issue_ok(self, **extra):
        response = self._issue(**extra)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def _poll(self, issued, **overrides):
        data = {
            'grant_type': DEVICE_GRANT,
            'device_code': issued['device_code'],
            'client_id': CLI_CLIENT,
        }
        data.update(overrides)
        return self.client.post('/oauth/token', data)

    def _confirm(self, user_code):
        return self.client.post('/oauth/cli/device', {'user_code': user_code})

    def _approve(self, decision='approve'):
        return self.client.post('/oauth/cli/device', {'decision': decision})

    def _claims(self, token):
        return jwt.decode(token, options={'verify_signature': False})

    def test_metadata_stays_mcp_and_code_response_shape(self):
        meta = self.client.get('/.well-known/oauth-authorization-server')
        self.assertEqual(meta.status_code, 200)
        self.assertEqual(meta.json()['device_authorization_endpoint'], 'https://identity.test/oauth/mcp/device/code')
        self.assertNotIn('/oauth/cli/device/code', meta.json()['device_authorization_endpoint'])

        with self.assertLogs('apps.authapi.cli_device', level='INFO') as captured:
            response = self._issue(
                _json=True,
                REMOTE_ADDR='203.0.113.8',
                HTTP_USER_AGENT='ShelluiCLI/1.0',
            )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response['Cache-Control'], 'no-store')
        body = response.json()
        self.assertEqual(
            set(body),
            {
                'device_code',
                'user_code',
                'verification_uri',
                'verification_uri_complete',
                'expires_in',
                'interval',
            },
        )
        self.assertRegex(body['user_code'], USER_CODE_RE)
        self.assertNotRegex(body['user_code'], r'[01OI]')
        self.assertGreater(len(body['device_code']), 20)
        self.assertNotEqual(body['device_code'], body['user_code'])
        self.assertEqual(body['verification_uri'], 'https://identity.test/oauth/cli/device')
        self.assertEqual(
            body['verification_uri_complete'],
            f'https://identity.test/oauth/cli/device?user_code={body["user_code"]}',
        )
        self.assertEqual(body['expires_in'], 600)
        self.assertEqual(body['interval'], 5)
        log_lines = '\n'.join(captured.output)
        self.assertNotIn(body['device_code'], log_lines)
        self.assertNotIn(body['user_code'], log_lines)
        self.assertNotIn(body['user_code'].replace('-', ''), log_lines)

        row = CliDeviceAuthorization.objects.get()
        self.assertEqual(row.kind, 'cli')
        self.assertEqual(row.client_id, CLI_CLIENT)
        self.assertEqual(row.device_code_digest, hash_authorization_code(body['device_code']))
        self.assertEqual(row.user_code_digest, hash_authorization_code(body['user_code'].replace('-', '')))
        self.assertNotEqual(row.device_code_digest, body['device_code'])
        self.assertNotIn(body['device_code'], row.device_code_digest)
        self.assertEqual(row.company_id, self.company.id)
        self.assertEqual(row.status, CliDeviceAuthorization.STATUS_PENDING)
        self.assertEqual(row.request_ip, '203.0.113.8')
        self.assertEqual(row.request_user_agent, 'ShelluiCLI/1.0')

    def test_form_body_and_validation_errors(self):
        form = self._issue()
        self.assertEqual(form.status_code, 200, form.content)
        missing_client = self.client.post('/oauth/cli/device/code', {'company_id': self.company.id})
        self.assertEqual(missing_client.status_code, 400)
        self.assertEqual(missing_client.json()['error'], 'invalid_request')
        unknown_client = self._issue(client_id='hermes-cli-test')
        self.assertEqual(unknown_client.status_code, 401)
        self.assertEqual(unknown_client.json()['error'], 'invalid_client')
        missing_company = self.client.post('/oauth/cli/device/code', {'client_id': CLI_CLIENT})
        self.assertEqual(missing_company.json()['error'], 'invalid_request')
        bad_company = self._issue(company_id='nope')
        self.assertEqual(bad_company.json()['error'], 'invalid_request')
        unknown = self._issue(company_id=999999)
        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(unknown.json()['error'], 'invalid_request')
        self.assertEqual(CliDeviceAuthorization.objects.count(), 1)

    def test_pending_slow_down_deny_expiry_and_single_use(self):
        issued = self._issue_ok(REMOTE_ADDR='203.0.113.9', HTTP_USER_AGENT='ShelluiCLI/9')
        pending = self._poll(issued)
        self.assertEqual(pending.status_code, 400)
        self.assertEqual(pending.json()['error'], 'authorization_pending')
        self.assertEqual(pending['Cache-Control'], 'no-store')
        slowed = self._poll(issued)
        self.assertEqual(slowed.json()['error'], 'slow_down')
        self.assertIn('error_description', slowed.json())
        row = CliDeviceAuthorization.objects.get()
        self.assertEqual(row.poll_interval, 10)

        self.client.force_login(self.user)
        confirmed = self._confirm(issued['user_code'].lower().replace('-', ' '))
        self.assertEqual(confirmed.status_code, 302)
        self.assertEqual(confirmed['Location'], '/oauth/cli/device')
        continue_page = self.client.get('/oauth/cli/device')
        self.assertContains(continue_page, 'Continue as ella@acme.com')
        self.assertContains(continue_page, 'Use another account')
        self.assertNotContains(continue_page, 'name="decision"')
        continued = self.client.post('/oauth/cli/device', {'account_choice': 'continue'})
        self.assertEqual(continued.status_code, 302)
        consent = self.client.get('/oauth/cli/device')
        self.assertEqual(consent.status_code, 200)
        self.assertContains(consent, 'Sign in the Shellui CLI on another device')
        self.assertContains(consent, 'Acme')
        self.assertContains(consent, '203.0.113.9')
        self.assertContains(consent, 'ShelluiCLI/9')
        self.assertContains(consent, issued['user_code'])
        self.assertContains(consent, 'name="decision" value="approve"')
        self.assertContains(consent, 'name="decision" value="deny"')
        self.assertNotIn(issued['device_code'], consent.content.decode())
        self.assertEqual(consent['X-Frame-Options'], 'DENY')
        self.assertEqual(consent['Cache-Control'], 'no-store')

        denied = self._approve('deny')
        self.assertEqual(denied.status_code, 302)
        denied_page = self.client.get('/oauth/cli/device')
        self.assertContains(denied_page, 'You denied access. You can close this page.')
        first = self._poll(issued)
        second = self._poll(issued)
        self.assertEqual(first.json()['error'], 'access_denied')
        self.assertEqual(second.json()['error'], 'access_denied')
        self.assertEqual(CliDeviceAuthorization.objects.get().status, CliDeviceAuthorization.STATUS_DENIED)
        self.assertEqual(RefreshTokenSession.objects.count(), 0)
        self.assertEqual(Agent.objects.count(), 0)

        expired = self._issue_ok()
        grant = CliDeviceAuthorization.objects.get(user_code_digest=hash_authorization_code(expired['user_code'].replace('-', '')))
        grant.expires_at = timezone.now() - timedelta(seconds=1)
        grant.save(update_fields=['expires_at'])
        late = self._poll(expired)
        self.assertEqual(late.json()['error'], 'expired_token')
        grant.refresh_from_db()
        self.assertEqual(grant.status, CliDeviceAuthorization.STATUS_EXPIRED)

        fresh = self._issue_ok(REMOTE_ADDR='198.51.100.7', HTTP_USER_AGENT='ShelluiCLI/fresh')
        self._confirm(fresh['user_code'])
        approved = self._approve()
        self.assertEqual(approved.status_code, 302)
        done = self.client.get('/oauth/cli/device')
        self.assertContains(done, 'CLI signed in')
        audit = EventLog.objects.get(event_type='identity.auth.login.succeeded', data__device_kind='cli')
        self.assertEqual(audit.user_id, self.user.id)
        self.assertEqual(audit.company_id, self.company.id)
        self.assertEqual(audit.data['provider'], 'cli')
        self.assertEqual(audit.data['device_kind'], 'cli')
        self.assertEqual(audit.data['user_agent'], 'ShelluiCLI/fresh')
        self.assertEqual(audit.data['ip_hash'], hash_ip('198.51.100.7'))
        self.assertNotIn(fresh['device_code'], json.dumps(audit.data))

        stale = CliDeviceAuthorization.objects.get(user_code_digest=hash_authorization_code(fresh['user_code'].replace('-', '')))
        stale.expires_at = timezone.now() - timedelta(seconds=1)
        stale.save(update_fields=['expires_at'])
        self.assertEqual(self._poll(fresh).json()['error'], 'expired_token')
        self.assertEqual(RefreshTokenSession.objects.count(), 0)

        live = self._issue_ok(HTTP_USER_AGENT='ShelluiCLI/live')
        self._confirm(live['user_code'])
        self._approve()
        token = self._poll(live)
        self.assertEqual(token.status_code, 200, token.content)
        payload = token.json()
        self.assertEqual(
            set(payload),
            {'access_token', 'refresh_token', 'token_type', 'expires_in', 'expires_at'},
        )
        self.assertEqual(payload['token_type'], 'bearer')
        access = self._claims(payload['access_token'])
        refresh = self._claims(payload['refresh_token'])
        from apps.authapi.views import _issue_shellui_tokens

        browser = self._claims(
            _issue_shellui_tokens(self.user, company=self.company, oauth_provider='cli')['access_token']
        )
        self.assertEqual(access.get('aud'), browser.get('aud'))
        self.assertEqual(access['company_id'], self.company.id)
        self.assertEqual(access['company_id'], browser['company_id'])
        self.assertEqual(access['email'], 'ella@acme.com')
        self.assertNotIn('agent_id', access)
        self.assertNotIn('cli_staff_session_exp', access)
        self.assertNotIn('cli_staff_session_exp', refresh)
        self.assertIn('sid', access)
        lifetime = int(self._claims_lifetime())
        self.assertAlmostEqual(refresh['exp'] - refresh['iat'], lifetime, delta=5)
        self.assertLessEqual(payload['expires_in'], 300)
        self.assertGreater(payload['expires_in'], 290)
        row = CliDeviceAuthorization.objects.get(user_code_digest=hash_authorization_code(live['user_code'].replace('-', '')))
        self.assertEqual(row.status, CliDeviceAuthorization.STATUS_CONSUMED)
        again = self._poll(live)
        self.assertEqual(again.json()['error'], 'invalid_grant')
        self.assertEqual(Agent.objects.count(), 0)

        listed = self.client.get('/api/v1/sessions', HTTP_AUTHORIZATION=f'Bearer {payload["access_token"]}')
        self.assertEqual(listed.status_code, 200, listed.content)
        sessions = listed.json()['sessions']
        cli_rows = [item for item in sessions if item['kind'] == 'cli']
        self.assertEqual(len(cli_rows), 1)
        self.assertEqual(cli_rows[0]['user_agent'], 'ShelluiCLI/live')
        self.assertTrue(cli_rows[0]['current'])
        session_id = cli_rows[0]['id']
        self.assertTrue(RefreshTokenSession.objects.filter(pk=session_id, kind='cli', revoked_at__isnull=True).exists())

        refreshed = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            data=json.dumps({'grant_type': 'refresh_token', 'refresh_token': payload['refresh_token']}),
            content_type='application/json',
        )
        self.assertEqual(refreshed.status_code, 200, refreshed.content)
        rotated = refreshed.json()['refresh_token']
        self.assertEqual(refreshed.json()['token_type'], 'bearer')

        revoked = self.client.post(
            f'/api/v1/sessions/{session_id}/revoke',
            HTTP_AUTHORIZATION=f'Bearer {payload["access_token"]}',
        )
        self.assertEqual(revoked.status_code, 404)
        current = self.client.get(
            '/api/v1/sessions',
            HTTP_AUTHORIZATION=f'Bearer {refreshed.json()["access_token"]}',
        )
        current_id = next(item['id'] for item in current.json()['sessions'] if item['kind'] == 'cli' and item['current'])
        gone = self.client.post(
            f'/api/v1/sessions/{current_id}/revoke',
            HTTP_AUTHORIZATION=f'Bearer {refreshed.json()["access_token"]}',
        )
        self.assertEqual(gone.status_code, 200, gone.content)
        self.assertTrue(gone.json()['revoked'])
        after = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            data=json.dumps({'grant_type': 'refresh_token', 'refresh_token': rotated}),
            content_type='application/json',
        )
        self.assertEqual(after.status_code, 401)

    def _claims_lifetime(self):
        from django.conf import settings

        return settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds()

    def test_staff_password_session_is_capped_and_magic_link_is_refused(self):
        issued = self._issue_ok(HTTP_USER_AGENT='ShelluiCLI/staff')
        page = self.client.get('/oauth/cli/device', {'user_code': issued['user_code']})
        self.assertContains(page, 'Sign in the Shellui CLI on another device')
        self.assertNotContains(page, 'Acme')
        confirmed = self._confirm(issued['user_code'])
        self.assertRedirects(confirmed, '/oauth/cli/signin', fetch_redirect_response=False)
        signin = self.client.get('/oauth/cli/signin')
        self.assertContains(signin, 'Acme')
        self.assertContains(signin, 'Staff accounts sign in with a password or single sign-on.')
        self.assertContains(signin, 'name="password"')
        self.assertContains(signin, 'name="email"')

        with mock.patch('apps.authapi.magic_link_views.deliver_magic_link_email') as deliver:
            staff_mail = self.client.post('/oauth/cli/signin', {'email': 'staff@acme.com'})
        self.assertEqual(staff_mail.status_code, 200)
        deliver.assert_not_called()
        self.assertFalse(MagicLinkToken.objects.filter(email='staff@acme.com').exists())
        self.assertContains(staff_mail, 'a sign-in link is on its way')

        bad = self.client.post(
            '/oauth/cli/signin',
            {'email': 'staff@acme.com', 'password': 'wrong-password'},
        )
        self.assertContains(bad, 'did not match')
        signed = self.client.post(
            '/oauth/cli/signin',
            {'email': 'staff@acme.com', 'password': 'staff-secret'},
        )
        self.assertRedirects(signed, '/oauth/cli/device', fetch_redirect_response=False)
        consent = self.client.get('/oauth/cli/device')
        self.assertContains(consent, 'Allow')
        self._approve()
        token = self._poll(issued)
        self.assertEqual(token.status_code, 200, token.content)
        refresh = self._claims(token.json()['refresh_token'])
        access = self._claims(token.json()['access_token'])
        self.assertNotIn('cli_staff_session_exp', access)
        self.assertIn('cli_staff_session_exp', refresh)
        self.assertAlmostEqual(refresh['cli_staff_session_exp'] - refresh['iat'], 12 * 3600, delta=5)
        self.assertAlmostEqual(refresh['exp'] - refresh['iat'], 12 * 3600, delta=5)
        self.assertLess(refresh['exp'] - refresh['iat'], 7 * 24 * 3600)
        self.assertTrue(access['user_metadata']['is_staff'])
        session = RefreshTokenSession.objects.get(user=self.staff, kind='cli')
        self.assertAlmostEqual((session.expires_at - timezone.now()).total_seconds(), 12 * 3600, delta=15)

        rotated = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            data=json.dumps({'grant_type': 'refresh_token', 'refresh_token': token.json()['refresh_token']}),
            content_type='application/json',
        )
        self.assertEqual(rotated.status_code, 200, rotated.content)
        new_refresh = self._claims(rotated.json()['refresh_token'])
        self.assertEqual(new_refresh['cli_staff_session_exp'], refresh['cli_staff_session_exp'])
        self.assertLessEqual(new_refresh['exp'], refresh['cli_staff_session_exp'])

    def test_superuser_is_allowed_with_the_staff_cap(self):
        issued = self._issue_ok()
        self.client.force_login(self.superuser)
        self._confirm(issued['user_code'])
        self._approve()
        token = self._poll(issued)
        self.assertEqual(token.status_code, 200, token.content)
        refresh = self._claims(token.json()['refresh_token'])
        self.assertAlmostEqual(refresh['exp'] - refresh['iat'], 12 * 3600, delta=5)
        self.assertFalse(Agent.objects.exists())

    def test_magic_link_signs_in_a_member_and_mcp_codes_stay_separate(self):
        issued = self._issue_ok(HTTP_USER_AGENT='ShelluiCLI/magic')
        self._confirm(issued['user_code'])
        sent = {}

        def fake_deliver(**kwargs):
            sent['token'] = kwargs['raw_token']
            sent['redirect_to'] = kwargs['row'].redirect_to

        with mock.patch('apps.authapi.magic_link_views.deliver_magic_link_email', side_effect=fake_deliver):
            mailed = self.client.post('/oauth/cli/signin', {'email': 'ella@acme.com'})
        self.assertEqual(mailed.status_code, 200)
        self.assertEqual(sent['redirect_to'], 'https://identity.test/oauth/cli/signin/complete')
        self.assertIn(sent['token'], build_magic_link_verify_url(token=sent['token'], company_id=self.company.id))
        verify = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': sent['token'], 'company_id': str(self.company.id)},
            HTTP_ACCEPT='text/html',
        )
        self.assertEqual(verify.status_code, 302)
        self.assertEqual(verify['Location'], '/oauth/cli/device')
        consent = self.client.get('/oauth/cli/device')
        self.assertContains(consent, 'Allow')
        self._approve()

        mcp = self.client.post(
            '/oauth/mcp/device/code',
            {'client_id': self.mcp_client.client_id, 'resource': self.resource},
        )
        self.assertEqual(mcp.status_code, 200, mcp.content)
        mcp_body = mcp.json()
        cross_cli = self._poll(mcp_body)
        self.assertEqual(cross_cli.json()['error'], 'invalid_grant')
        self.assertFalse(RefreshTokenSession.objects.filter(user=self.user).exists())
        self.assertEqual(McpDeviceAuthorization.objects.get().status, McpDeviceAuthorization.STATUS_PENDING)

        cross_mcp = self.client.post(
            '/oauth/token',
            {
                'grant_type': DEVICE_GRANT,
                'device_code': issued['device_code'],
                'client_id': self.mcp_client.client_id,
                'resource': self.resource,
            },
        )
        self.assertEqual(cross_mcp.json()['error'], 'invalid_grant')
        self.assertEqual(Agent.objects.count(), 0)
        self.assertEqual(
            CliDeviceAuthorization.objects.get(user_code_digest=hash_authorization_code(issued['user_code'].replace('-', ''))).status,
            CliDeviceAuthorization.STATUS_APPROVED,
        )

        token = self._poll(issued)
        self.assertEqual(token.status_code, 200, token.content)
        issued_claims = self._claims(token.json()['access_token'])
        self.assertNotIn('agent_id', issued_claims)
        from apps.authapi.views import _issue_shellui_tokens

        browser = self._claims(
            _issue_shellui_tokens(self.user, company=self.company, oauth_provider='cli')['access_token']
        )
        self.assertEqual(issued_claims.get('aud'), browser.get('aud'))
        self.assertEqual(issued_claims['email'], 'ella@acme.com')

    def test_outsider_cannot_approve(self):
        issued = self._issue_ok()
        self.client.force_login(self.outsider)
        blocked = self._confirm(issued['user_code'])
        self.assertRedirects(blocked, '/oauth/cli/signin', fetch_redirect_response=False)
        page = self.client.get('/oauth/cli/signin')
        self.assertContains(page, 'name="email"')
        self.assertNotContains(page, 'Continue as')
        self.assertEqual(self._poll(issued).json()['error'], 'authorization_pending')

    def test_code_entry_is_throttled(self):
        limits = {'cli_device_verify': {'limit': 3, 'window': 300}}
        with override_settings(AUTH_RATE_LIMIT_ENABLED=True, AUTH_RATE_LIMITS=limits):
            codes = [
                self.client.post('/oauth/cli/device', {'user_code': f'ABCD-EFG{n}'}).status_code for n in range(4)
            ]
        self.assertEqual(codes[:3], [400, 400, 400])
        self.assertEqual(codes[3], 429)

    def test_verification_page_french_and_csrf_and_openapi(self):
        page = self.client.get('/oauth/cli/device', HTTP_ACCEPT_LANGUAGE='fr')
        self.assertContains(page, 'Connecter le CLI Shellui sur un autre appareil')
        self.assertContains(page, 'csrfmiddlewaretoken')
        csrf_client = Client(enforce_csrf_checks=True)
        open_post = csrf_client.post(
            '/oauth/cli/device/code',
            {'client_id': CLI_CLIENT, 'company_id': self.company.id},
        )
        self.assertEqual(open_post.status_code, 200)
        blocked = csrf_client.post('/oauth/cli/device', {'user_code': 'ABCD-EFGH'})
        self.assertEqual(blocked.status_code, 403)

        schema = self.client.get('/api/schema/')
        self.assertEqual(schema.status_code, 200)
        body = schema.content.decode()
        self.assertIn('/oauth/cli/device/code', body)
        self.assertIn('oauth_cli_device_authorization', body)
        self.assertIn('/api/v1/sessions', body)
        self.assertIn('api_v1_sessions_list', body)
        self.assertIn('api_v1_sessions_revoke', body)
