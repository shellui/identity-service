"""RFC 8628 device authorization for company MCP agents."""

from __future__ import annotations

import json
import re
from datetime import timedelta

import jwt
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.agents.models import Agent, AgentRefreshSession, McpCallLog, McpDeviceAuthorization, McpOAuthClient
from apps.agents.oauth_codes import hash_authorization_code
from apps.agents.personal_agent_tokens import personal_agent_max_lifetime
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


@override_settings(**SETTINGS)
class McpDeviceFlowTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Acme', slug='acme-device', enable_magic_link=True)
        self.other = Company.objects.create(name='Other Co', slug='other-device')
        self.user = User.objects.create_user(username='ella', email='ella@acme.com', password='unused')
        self.company.owners.add(self.user)
        set_company_access(self.company, self.user, enabled=True)
        self.outsider = User.objects.create_user(username='out', email='out@other.com', password='unused')
        self.other.owners.add(self.outsider)
        set_company_access(self.other, self.outsider, enabled=True)
        self.staff = User.objects.create_user(username='staff', email='staff@acme.com', password='unused', is_staff=True)
        self.company.owners.add(self.staff)
        set_company_access(self.company, self.staff, enabled=True)
        self.client_row = McpOAuthClient.objects.create(
            client_id='hermes-1',
            client_name='Hermes',
            redirect_uris=['http://127.0.0.1/callback'],
        )
        self.resource = f'https://ai.test/c/{self.company.id}/mcp'
        self.other_resource = f'https://ai.test/c/{self.other.id}/mcp'

    def _issue(self, **overrides):
        payload = {
            'client_id': self.client_row.client_id,
            'resource': self.resource,
            'scope': 'mcp',
        }
        payload.update(overrides)
        return self.client.post('/oauth/mcp/device/code', payload)

    def _poll(self, issued, **overrides):
        path = overrides.pop('_path', '/oauth/token')
        data = {
            'grant_type': DEVICE_GRANT,
            'device_code': issued['device_code'],
            'client_id': self.client_row.client_id,
            'resource': self.resource,
        }
        data.update(overrides)
        return self.client.post(path, data)

    def _confirm(self, user_code, client=None):
        client = client or self.client
        return client.post('/oauth/mcp/device', {'user_code': user_code})

    def _approve(self, *, services=None, decision='approve'):
        return self.client.post(
            '/oauth/mcp/device',
            {
                'decision': decision,
                'agent_name': 'Hermes',
                'access_mode': 'ask',
                'read_level': 'safe',
                'services': services or ['identity'],
            },
        )

    def test_device_token_lock_targets_device_row_only(self):
        """Nullable agent/user joins must not be locked (Postgres FOR UPDATE outer-join ban)."""
        qs = (
            McpDeviceAuthorization.objects.select_for_update(of=('self',))
            .select_related('client', 'agent', 'user', 'company')
            .order_by()
        )
        self.assertTrue(qs.query.select_for_update)
        self.assertEqual(tuple(qs.query.select_for_update_of), ('self',))
        if connection.vendor == 'postgresql':
            sql = str(qs.query).upper()
            self.assertIn('FOR UPDATE OF', sql)
            self.assertIn('MCPDEVICEAUTHORIZATION', sql.replace('"', ''))

    def test_metadata_and_code_response(self):
        meta = self.client.get('/.well-known/oauth-authorization-server')
        self.assertEqual(meta.status_code, 200)
        self.assertEqual(meta.json()['device_authorization_endpoint'], 'https://identity.test/oauth/mcp/device/code')
        self.assertIn(DEVICE_GRANT, meta.json()['grant_types_supported'])

        with self.assertLogs('apps.agents.oauth_device', level='INFO') as captured:
            response = self._issue()
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response['Cache-Control'], 'no-store')
        body = response.json()
        log_lines = '\n'.join(captured.output)
        self.assertRegex(body['user_code'], USER_CODE_RE)
        self.assertNotRegex(body['user_code'], r'[01OI]')
        self.assertGreater(len(body['device_code']), 20)
        self.assertNotEqual(body['device_code'], body['user_code'])
        self.assertEqual(body['verification_uri'], 'https://identity.test/oauth/mcp/device')
        self.assertEqual(
            body['verification_uri_complete'],
            f'https://identity.test/oauth/mcp/device?user_code={body["user_code"]}',
        )
        self.assertEqual(body['expires_in'], 600)
        self.assertEqual(body['interval'], 5)
        self.assertNotIn(body['device_code'], log_lines)
        self.assertNotIn(body['user_code'], log_lines)
        self.assertNotIn(body['user_code'].replace('-', ''), log_lines)

        row = McpDeviceAuthorization.objects.get()
        self.assertEqual(row.device_code_digest, hash_authorization_code(body['device_code']))
        self.assertEqual(row.user_code_digest, hash_authorization_code(body['user_code'].replace('-', '')))
        self.assertNotEqual(row.device_code_digest, body['device_code'])
        self.assertNotIn(body['device_code'], row.device_code_digest)
        self.assertEqual(row.company_id, self.company.id)
        self.assertEqual(row.resource, self.resource)
        self.assertEqual(row.status, McpDeviceAuthorization.STATUS_PENDING)

    def test_full_flow_pending_approve_token_refresh_revoke_and_reuse(self):
        issued = self._issue().json()
        pending = self._poll(issued, _path='/oauth/mcp/token')
        self.assertEqual(pending.status_code, 400)
        self.assertEqual(pending.json()['error'], 'authorization_pending')
        self.assertEqual(pending['Cache-Control'], 'no-store')

        self.client.force_login(self.user)
        typed = issued['user_code'].lower().replace('-', ' ')
        confirmed = self._confirm(typed)
        self.assertEqual(confirmed.status_code, 302)
        self.assertEqual(confirmed['Location'], '/oauth/mcp/device')
        continue_page = self.client.get('/oauth/mcp/device')
        self.assertContains(continue_page, 'Continue as ella@acme.com')
        self.assertNotContains(continue_page, 'name="decision"')
        self.client.post('/oauth/mcp/device', {'account_choice': 'continue'})
        consent = self.client.get('/oauth/mcp/device')
        self.assertEqual(consent.status_code, 200)
        self.assertContains(consent, 'Hermes')
        self.assertContains(consent, 'Acme')
        self.assertContains(consent, 'Allow Hermes?')
        self.assertContains(consent, 'name="decision" value="approve"')
        self.assertNotIn(issued['device_code'], consent.content.decode())
        self.assertEqual(consent['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'", consent['Content-Security-Policy'])
        self.assertEqual(consent['Cache-Control'], 'no-store')

        approved = self._approve()
        self.assertEqual(approved.status_code, 302)
        done = self.client.get('/oauth/mcp/device')
        self.assertContains(done, 'Agent connected')
        self.assertContains(done, 'You approved this agent')
        # Terminal grant is dropped from the session so a later Hermes attempt is not
        # masked by a sticky "Agent connected" page.
        again = self.client.get('/oauth/mcp/device')
        self.assertEqual(again.status_code, 200)
        self.assertContains(again, 'name="user_code"')
        self.assertNotContains(again, 'Agent connected')

        token = self._poll(issued)
        self.assertEqual(token.status_code, 200, token.content)
        payload = token.json()
        self.assertEqual(payload['token_type'], 'Bearer')
        self.assertIn('refresh_token', payload)
        self.assertEqual(payload['expires_in'], 900)
        claims = jwt.decode(payload['access_token'], options={'verify_signature': False})
        agent = Agent.objects.get()
        self.assertEqual(claims['aud'], self.resource)
        self.assertEqual(claims['agent_id'], str(agent.id))
        self.assertEqual(claims['company_id'], self.company.id)
        self.assertEqual(claims['mcp_access'], 'ask')
        self.assertEqual(claims['mcp_read'], 'safe')
        self.assertFalse(claims['mcp_destructive'])
        self.assertEqual(claims['scope'], 'identity ai')
        self.assertEqual(claims['grant_version'], 0)
        self.assertEqual(claims['sub'], f'agent:{agent.id}')
        self.assertEqual(claims['owner_user_id'], self.user.pk)
        self.assertIsInstance(claims['owner_user_id'], int)
        self.assertNotIsInstance(claims['owner_user_id'], bool)
        self.assertLessEqual(claims['exp'] - claims['iat'], 900)
        self.assertGreater(agent.expires_at, timezone.now() + timedelta(days=89))
        self.assertLessEqual(agent.expires_at, timezone.now() + personal_agent_max_lifetime() + timedelta(minutes=1))
        self.assertEqual(agent.created_by_id, self.user.id)
        self.assertEqual(agent.oauth_client_id, self.client_row.id)
        self.assertFalse(agent.allow_destructive_without_asking)

        log = McpCallLog.objects.get(tool='oauth.device.approved')
        blob = json.dumps(log.arguments_redacted)
        self.assertEqual(log.path, '/oauth/mcp/device')
        self.assertNotIn(issued['device_code'], blob)
        self.assertNotIn(issued['user_code'].replace('-', ''), blob)
        self.assertEqual(log.arguments_redacted['grant_type'], DEVICE_GRANT)

        row = McpDeviceAuthorization.objects.get()
        self.assertEqual(row.status, McpDeviceAuthorization.STATUS_CONSUMED)
        self.assertIsNotNone(row.consumed_at)

        from apps.authapi.views import _issue_shellui_tokens

        member = _issue_shellui_tokens(self.user, company=self.company)['access_token']
        listed = self.client.get(
            '/api/v1/mcp/personal/agents',
            HTTP_AUTHORIZATION=f'Bearer {member}',
            HTTP_X_SHELLUI_COMPANY_ID=str(self.company.id),
        )
        self.assertEqual(listed.status_code, 200, listed.content)
        agents = listed.json()['agents']
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]['kind'], 'oauth')
        self.assertEqual(agents[0]['id'], str(agent.id))
        self.assertEqual(agents[0]['oauth_client_id'], self.client_row.client_id)
        self.assertTrue(agents[0]['is_active'])
        self.assertIsNotNone(agents[0]['expires_at'])

        refreshed = self.client.post(
            '/oauth/token',
            {
                'grant_type': 'refresh_token',
                'refresh_token': payload['refresh_token'],
                'resource': self.resource,
            },
        )
        self.assertEqual(refreshed.status_code, 200, refreshed.content)
        self.assertIn('access_token', refreshed.json())
        refreshed_claims = jwt.decode(refreshed.json()['access_token'], options={'verify_signature': False})
        self.assertEqual(refreshed_claims['owner_user_id'], self.user.pk)
        self.assertEqual(refreshed_claims['aud'], claims['aud'])
        self.assertEqual(refreshed_claims['scope'], claims['scope'])
        rotated = refreshed.json()['refresh_token']

        revoked = self.client.post(
            f'/api/v1/mcp/personal/agents/{agent.id}/revoke',
            HTTP_AUTHORIZATION=f'Bearer {member}',
            HTTP_X_SHELLUI_COMPANY_ID=str(self.company.id),
        )
        self.assertEqual(revoked.status_code, 200, revoked.content)
        self.assertFalse(revoked.json()['agent']['is_active'])
        agent.refresh_from_db()
        self.assertIsNotNone(agent.revoked_at)
        self.assertFalse(AgentRefreshSession.objects.filter(agent=agent, revoked_at__isnull=True).exists())
        again = self.client.post(
            '/oauth/token',
            {'grant_type': 'refresh_token', 'refresh_token': rotated, 'resource': self.resource},
        )
        self.assertEqual(again.status_code, 400)
        self.assertEqual(again.json()['error'], 'invalid_grant')

        reuse = self._poll(issued)
        self.assertEqual(reuse.status_code, 400)
        self.assertEqual(reuse.json()['error'], 'invalid_grant')
        self.assertEqual(Agent.objects.count(), 1)

    def test_signed_out_user_confirms_code_on_company_signin_page(self):
        issued = self._issue().json()
        page = self.client.get('/oauth/mcp/device', {'user_code': issued['user_code']})
        self.assertContains(page, f'value="{issued["user_code"]}"')
        self.assertNotContains(page, 'Acme')
        self.assertNotIn(issued['device_code'], page.content.decode())
        confirmed = self._confirm(issued['user_code'])
        self.assertRedirects(confirmed, '/oauth/mcp/signin', fetch_redirect_response=False)
        signin = self.client.get('/oauth/mcp/signin')
        self.assertEqual(signin.status_code, 200)
        body = signin.content.decode()
        self.assertIn('Hermes wants to use MCP for your company.', body)
        self.assertNotIn('Acme', body)
        self.assertIn('name="email"', body)
        self.assertEqual(signin['X-Frame-Options'], 'DENY')
        self.client.force_login(self.user)
        continue_page = self.client.get('/oauth/mcp/device')
        self.assertContains(continue_page, 'Continue as ella@acme.com')
        self.client.post('/oauth/mcp/device', {'account_choice': 'continue'})
        consent = self.client.get('/oauth/mcp/device')
        self.assertContains(consent, 'Acme')
        self.assertContains(consent, 'Allow Hermes?')

    def test_deny(self):
        issued = self._issue().json()
        self.client.force_login(self.user)
        self._confirm(issued['user_code'])
        denied = self._approve(decision='deny')
        self.assertEqual(denied.status_code, 302)
        page = self.client.get('/oauth/mcp/device')
        self.assertContains(page, 'You denied access. You can close this page.')
        self.assertEqual(Agent.objects.count(), 0)
        first = self._poll(issued)
        second = self._poll(issued)
        self.assertEqual(first.json()['error'], 'access_denied')
        self.assertEqual(second.json()['error'], 'access_denied')
        self.assertEqual(McpDeviceAuthorization.objects.get().status, McpDeviceAuthorization.STATUS_DENIED)

    def test_expiry_before_approval_and_after_approval_before_poll(self):
        issued = self._issue().json()
        row = McpDeviceAuthorization.objects.get()
        row.expires_at = timezone.now() - timedelta(seconds=1)
        row.save(update_fields=['expires_at'])
        expired = self._poll(issued)
        self.assertEqual(expired.status_code, 400)
        self.assertEqual(expired.json()['error'], 'expired_token')
        row.refresh_from_db()
        self.assertEqual(row.status, McpDeviceAuthorization.STATUS_EXPIRED)
        page = self._confirm(issued['user_code'])
        self.assertContains(page, 'data-error-code="device_code_expired"', status_code=400)

        fresh = self._issue().json()
        self.client.force_login(self.user)
        self._confirm(fresh['user_code'])
        self._approve()
        self.assertEqual(Agent.objects.count(), 1)
        grant = McpDeviceAuthorization.objects.get(user_code_digest=hash_authorization_code(fresh['user_code'].replace('-', '')))
        grant.expires_at = timezone.now() - timedelta(seconds=1)
        grant.save(update_fields=['expires_at'])
        late = self._poll(fresh)
        self.assertEqual(late.json()['error'], 'expired_token')
        agent = Agent.objects.get()
        agent.refresh_from_db()
        self.assertIsNotNone(agent.revoked_at)
        self.assertNotEqual(late.json()['error'], 'authorization_pending')

    def test_slow_down_then_pending_again_after_interval(self):
        issued = self._issue().json()
        first = self._poll(issued)
        second = self._poll(issued)
        self.assertEqual(first.json()['error'], 'authorization_pending')
        self.assertEqual(second.json()['error'], 'slow_down')
        row = McpDeviceAuthorization.objects.get()
        self.assertEqual(row.poll_interval, 10)
        row.last_poll_at = timezone.now() - timedelta(seconds=11)
        row.save(update_fields=['last_poll_at'])
        third = self._poll(issued)
        self.assertEqual(third.json()['error'], 'authorization_pending')
        self.assertEqual(McpDeviceAuthorization.objects.get().poll_interval, 10)

    def test_wrong_company_resource_and_member(self):
        issued = self._issue().json()
        wrong = self._poll(issued, resource=self.other_resource)
        self.assertEqual(wrong.status_code, 400)
        self.assertEqual(wrong.json()['error'], 'invalid_target')
        self.assertEqual(McpDeviceAuthorization.objects.get().status, McpDeviceAuthorization.STATUS_PENDING)
        still = self._poll(issued)
        self.assertEqual(still.json()['error'], 'authorization_pending')

        other_client = McpOAuthClient.objects.create(
            client_id='other-client',
            client_name='Other',
            redirect_uris=['http://127.0.0.1/callback'],
        )
        mismatch = self._poll(issued, client_id=other_client.client_id)
        self.assertEqual(mismatch.json()['error'], 'invalid_grant')

        self.client.force_login(self.outsider)
        blocked = self._confirm(issued['user_code'])
        self.assertRedirects(blocked, '/oauth/mcp/signin', fetch_redirect_response=False)
        page = self.client.get('/oauth/mcp/signin')
        self.assertContains(page, 'name="email"')
        self.assertNotContains(page, 'Continue as')
        self.assertEqual(Agent.objects.count(), 0)
        self.assertEqual(McpDeviceAuthorization.objects.get().status, McpDeviceAuthorization.STATUS_PENDING)

    def test_staff_cannot_approve(self):
        issued = self._issue().json()
        self.client.force_login(self.staff)
        refused = self._confirm(issued['user_code'])
        self.assertEqual(refused.status_code, 403)
        self.assertContains(refused, 'Staff accounts cannot authorize MCP agents.', status_code=403)
        self.assertEqual(Agent.objects.count(), 0)
        self.assertEqual(McpDeviceAuthorization.objects.get().status, McpDeviceAuthorization.STATUS_PENDING)
        # The first poll above was not made; this one is the first, so it is pending, not slow_down.
        self.assertEqual(self._poll(issued).json()['error'], 'authorization_pending')

    def test_unknown_client_bad_resource_and_registration_disabled(self):
        missing = self.client.post(
            '/oauth/mcp/device/code',
            {'client_id': 'nope', 'resource': self.resource},
        )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing.json()['error'], 'invalid_client')
        bad = self._issue(resource='https://evil.test/c/1/mcp')
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.json()['error'], 'invalid_target')
        plain = self._issue(resource='https://ai.test/mcp')
        self.assertEqual(plain.status_code, 400)
        self.assertEqual(plain.json()['error'], 'invalid_target')
        self.company.mcp_allow_dynamic_registration = False
        self.company.save(update_fields=['mcp_allow_dynamic_registration'])
        disabled = self._issue()
        self.assertEqual(disabled.status_code, 403)
        self.assertEqual(disabled.json()['error'], 'registration_disabled')

    def test_code_entry_is_throttled(self):
        limits = {'mcp_device_verify': {'limit': 3, 'window': 300}}
        with override_settings(AUTH_RATE_LIMIT_ENABLED=True, AUTH_RATE_LIMITS=limits):
            codes = [
                self.client.post('/oauth/mcp/device', {'user_code': f'ABCD-EFG{n}'}).status_code for n in range(4)
            ]
        self.assertEqual(codes[:3], [400, 400, 400])
        self.assertEqual(codes[3], 429)

    def test_verification_page_french_and_csrf(self):
        page = self.client.get('/oauth/mcp/device', HTTP_ACCEPT_LANGUAGE='fr')
        self.assertContains(page, 'Saisissez le code de votre agent')
        self.assertContains(page, 'csrfmiddlewaretoken')
        csrf_client = Client(enforce_csrf_checks=True)
        open_post = csrf_client.post(
            '/oauth/mcp/device/code',
            {'client_id': self.client_row.client_id, 'resource': self.resource},
        )
        self.assertEqual(open_post.status_code, 200)
        blocked = csrf_client.post('/oauth/mcp/device', {'user_code': 'ABCD-EFGH'})
        self.assertEqual(blocked.status_code, 403)

    def test_device_grant_is_in_openapi(self):
        schema = self.client.get('/api/schema/')
        self.assertEqual(schema.status_code, 200)
        body = schema.content.decode()
        self.assertIn('/oauth/mcp/device/code', body)
        self.assertIn('oauth_mcp_device_authorization', body)
        self.assertIn(DEVICE_GRANT, body)
