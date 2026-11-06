import json
import time
import uuid
from datetime import timedelta

import jwt
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from shellui_django.mcp.internal import APPROVAL_AUDIENCE, APPROVAL_SCOPE, build_mcp_approval_assertion

from apps.actions.models import EventLog
from apps.agents.approval_links import sign_approval_fallback_token
from apps.agents.models import Agent, McpApprovalRequest, McpApprovalSessionGrant
from apps.agents.tests.mcp_test_settings import (
    TEST_AI_CALLER_SIGNING,
    TEST_CALLER_SIGNING,
    TRUSTED_AI_TEST_CALLER_SETTINGS,
    TRUSTED_TEST_CALLER_SETTINGS,
)
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

_APPROVAL_SETTINGS = {**TRUSTED_TEST_CALLER_SETTINGS, **TRUSTED_AI_TEST_CALLER_SETTINGS}


@override_settings(
    **_APPROVAL_SETTINGS,
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
    MCP_APPROVAL_SESSION_TTL_SECONDS=60,
    MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
)
class McpApprovalV1Tests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-approval-v1')
        self.owner = User.objects.create_user(username='owner-v1', email='owner@acme.com', password='unused')
        self.member = User.objects.create_user(username='member-v1', email='member@acme.com', password='unused')
        self.other = User.objects.create_user(username='other-v1', email='other@acme.com', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.member, enabled=True)
        set_company_access(self.company, self.other, enabled=True)
        self.agent = Agent.objects.create(company=self.company, name='Writer', created_by=self.member)
        self.other_agent = Agent.objects.create(company=self.company, name='Other', created_by=self.owner)

    def _token(self, user):
        from apps.authapi.views import _issue_shellui_tokens

        return _issue_shellui_tokens(user, company=self.company)['access_token']

    def _assertion(self, agent, *, args_hash='abc123', service='storage', action='write_file'):
        return build_mcp_approval_assertion(
            **TEST_CALLER_SIGNING,
            company_id=self.company.id,
            agent_id=str(agent.id),
            service=service,
            action=action,
            arguments_hash=args_hash,
            audience_url='https://identity.test',
        )

    def _ai_assertion(
        self,
        agent,
        *,
        args_hash='abc123',
        service='storage',
        action='write_file',
        lifetime_seconds=60,
        extra_claims=None,
    ):
        signing = TEST_AI_CALLER_SIGNING
        now = int(time.time())
        claims = {
            'iss': signing['issuer'],
            'aud': APPROVAL_AUDIENCE,
            'sub': f'agent:{agent.id}',
            'scope': APPROVAL_SCOPE,
            'company_id': self.company.id,
            'agent_id': str(agent.id),
            'service': service,
            'action': action,
            'arguments_hash': args_hash,
            'target': 'https://identity.test',
            'iat': now,
            'exp': now + lifetime_seconds,
            'jti': uuid.uuid4().hex,
        }
        if extra_claims:
            claims.update(extra_claims)
        token = jwt.encode(claims, signing['private_key_pem'], algorithm='RS256', headers={'kid': signing['kid']})
        return token.decode('utf-8') if isinstance(token, bytes) else token

    def _service_assertion_with_claims(
        self,
        agent,
        *,
        args_hash='abc123',
        service='storage',
        action='write_file',
        lifetime_seconds=60,
        extra_claims=None,
    ):
        signing = TEST_CALLER_SIGNING
        now = int(time.time())
        claims = {
            'iss': signing['issuer'],
            'aud': APPROVAL_AUDIENCE,
            'sub': f'agent:{agent.id}',
            'scope': APPROVAL_SCOPE,
            'company_id': self.company.id,
            'agent_id': str(agent.id),
            'service': service,
            'action': action,
            'arguments_hash': args_hash,
            'target': 'https://identity.test',
            'iat': now,
            'exp': now + lifetime_seconds,
            'jti': uuid.uuid4().hex,
        }
        if extra_claims:
            claims.update(extra_claims)
        token = jwt.encode(claims, signing['private_key_pem'], algorithm='RS256', headers={'kid': signing['kid']})
        return token.decode('utf-8') if isinstance(token, bytes) else token

    def _create_via_internal(self, agent=None, *, args_hash='abc123', **extra_body):
        agent = agent or self.agent
        body = {
            'arguments': {'path': '/tmp/x'},
            'is_destructive': False,
            'short_action_summary': 'Write /tmp/x',
            **extra_body,
        }
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-requests',
            data=json.dumps(body),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(agent, args_hash=args_hash)}',
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_member_lists_only_their_agents_pending(self):
        self._create_via_internal(self.agent, args_hash='a' * 64)
        self._create_via_internal(self.other_agent, args_hash='b' * 64)
        member_token = self._token(self.member)
        listed = self.client.get('/api/v1/mcp/approvals', HTTP_AUTHORIZATION=f'Bearer {member_token}')
        self.assertEqual(listed.status_code, 200)
        body = listed.json()
        self.assertEqual(body['pending_count'], len(body['approvals']))
        ids = {row['agent_id'] for row in body['approvals']}
        self.assertEqual(ids, {str(self.agent.id)})

    def test_owner_lists_all_pending(self):
        self._create_via_internal(self.agent, args_hash='a' * 64)
        self._create_via_internal(self.other_agent, args_hash='b' * 64)
        owner_token = self._token(self.owner)
        listed = self.client.get('/api/v1/mcp/approvals', HTTP_AUTHORIZATION=f'Bearer {owner_token}')
        self.assertEqual(len(listed.json()['approvals']), 2)

    def test_settings_decide_approve_and_deny_audit(self):
        created = self._create_via_internal()
        approval_id = created['id']
        token = self._token(self.member)
        approved = self.client.post(
            f'/api/v1/mcp/approvals/{approval_id}/decide',
            data=json.dumps({'decision': 'approve'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(approved.status_code, 200)
        event = EventLog.objects.filter(event_type='identity.mcp.approval_decision').latest('id')
        self.assertEqual(event.data['status'], 'approved')
        self.assertEqual(event.data['tool_name'], 'write_file')

        created2 = self._create_via_internal(args_hash='c' * 64)
        denied = self.client.post(
            f'/api/v1/mcp/approvals/{created2["id"]}/decide',
            data=json.dumps({'decision': 'deny'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(denied.status_code, 200)
        event2 = EventLog.objects.filter(event_type='identity.mcp.approval_decision').latest('id')
        self.assertEqual(event2.data['status'], 'denied')

    def test_client_allow_session_rejects_destructive(self):
        created = self._create_via_internal(is_destructive=True, args_hash='d' * 64)
        assertion = self._assertion(self.agent, args_hash='d' * 64)
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps({'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'conn-1'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        self.assertEqual(response.status_code, 409)

    def test_client_session_grant_and_check(self):
        created = self._create_via_internal(args_hash='e' * 64)
        assertion = self._assertion(self.agent, args_hash='e' * 64)
        decided = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {
                    'approval_id': created['id'],
                    'decision': 'allow_session',
                    'connection_id': 'conn-9',
                    'actor_email': 'member@acme.com',
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        self.assertEqual(decided.status_code, 200)
        self.assertEqual(decided.json()['audit_status'], 'client_session_allowed')
        grant = McpApprovalSessionGrant.objects.get(agent=self.agent, connection_id='conn-9')
        self.assertAlmostEqual(
            (grant.expires_at - timezone.now()).total_seconds(),
            60,
            delta=5,
        )
        check = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'conn-9', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash="e" * 64)}',
        )
        self.assertTrue(check.json()['session_allowed'])
        destructive = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'conn-9', 'is_destructive': True}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash="e2" * 32)}',
        )
        self.assertFalse(destructive.json()['session_allowed'])

    def test_session_revoke_on_disconnect(self):
        created = self._create_via_internal(args_hash='f' * 64)
        assertion = self._assertion(self.agent, args_hash='f' * 64)
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps({'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'c1'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        revoked = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-revoke',
            data=json.dumps({'connection_id': 'c1'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash="f" * 64)}',
        )
        self.assertTrue(revoked.json()['revoked'])

    def test_fallback_page_approve(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_file',
            arguments_hash='g' * 64,
            short_action_summary='Write file',
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        token = sign_approval_fallback_token(str(row.id))
        client = Client()
        client.force_login(self.member)
        url = f'/oauth/mcp/approval/{row.id}?token={token}'
        page = client.get(url)
        self.assertContains(page, 'Approve this action?')
        self.assertContains(page, 'Writer wants to run write_file on Acme')
        approved = client.post(url, {'decision': 'approve', 'token': token})
        self.assertContains(approved, 'Approved')
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_APPROVED)

    def test_fallback_expired_records_audit(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_file',
            arguments_hash='h' * 64,
            status=McpApprovalRequest.STATUS_PENDING,
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        token = sign_approval_fallback_token(str(row.id))
        client = Client()
        client.force_login(self.member)
        response = client.get(f'/oauth/mcp/approval/{row.id}?token={token}')
        self.assertContains(response, 'This approval is no longer valid')
        event = EventLog.objects.filter(event_type='identity.mcp.approval_decision').latest('id')
        self.assertEqual(event.data['status'], 'expired')

    def test_internal_state_marks_expired(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_file',
            arguments_hash='i' * 64,
            status=McpApprovalRequest.STATUS_PENDING,
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        assertion = self._assertion(self.agent, args_hash='i' * 64)
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-state',
            data='{}',
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        self.assertEqual(response.json()['status'], 'expired')
        row.refresh_from_db()
        self.assertTrue(row.expired_event_logged)

    def test_setup_session_uses_600_seconds_when_ai_mints_setup_claims(self):
        h = 's' * 64
        created = self._create_via_internal(args_hash=h)
        assertion = self._ai_assertion(
            self.agent,
            args_hash=h,
            lifetime_seconds=900,
            extra_claims={'setup_flow': True, 'mcp_session_ttl_seconds': 600},
        )
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'setup-conn'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        grant = McpApprovalSessionGrant.objects.get(agent=self.agent, connection_id='setup-conn')
        self.assertAlmostEqual((grant.expires_at - timezone.now()).total_seconds(), 600, delta=10)

    def test_setup_ttl_ignored_for_non_ai_caller(self):
        h = 't' * 64
        created = self._create_via_internal(args_hash=h)
        assertion = self._service_assertion_with_claims(
            self.agent,
            args_hash=h,
            lifetime_seconds=900,
            extra_claims={'setup_flow': True, 'mcp_session_ttl_seconds': 600},
        )
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'svc-setup'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        grant = McpApprovalSessionGrant.objects.get(agent=self.agent, connection_id='svc-setup')
        self.assertAlmostEqual((grant.expires_at - timezone.now()).total_seconds(), 60, delta=5)

    def test_setup_ttl_out_of_band_falls_back_to_default(self):
        h = 'u' * 64
        created = self._create_via_internal(args_hash=h)
        assertion = self._ai_assertion(
            self.agent,
            args_hash=h,
            lifetime_seconds=900,
            extra_claims={'setup_flow': True, 'mcp_session_ttl_seconds': 120},
        )
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'bad-band'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        grant = McpApprovalSessionGrant.objects.get(agent=self.agent, connection_id='bad-band')
        self.assertAlmostEqual((grant.expires_at - timezone.now()).total_seconds(), 60, delta=5)

    def test_setup_ttl_cannot_exceed_signed_assertion_lifetime(self):
        h = 'v' * 64
        created = self._create_via_internal(args_hash=h)
        assertion = self._ai_assertion(
            self.agent,
            args_hash=h,
            lifetime_seconds=120,
            extra_claims={'setup_flow': True, 'mcp_session_ttl_seconds': 600},
        )
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'short-jwt'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        grant = McpApprovalSessionGrant.objects.get(agent=self.agent, connection_id='short-jwt')
        self.assertAlmostEqual((grant.expires_at - timezone.now()).total_seconds(), 60, delta=5)

    def test_session_not_reused_across_connections(self):
        h = 'w' * 64
        created = self._create_via_internal(args_hash=h)
        assertion = self._assertion(self.agent, args_hash=h)
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'only-a'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        check_other = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'only-b', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h)}',
        )
        self.assertFalse(check_other.json()['session_allowed'])

    def test_expired_session_grant_is_not_allowed(self):
        past = timezone.now() - timedelta(seconds=1)
        McpApprovalSessionGrant.objects.create(
            agent=self.agent,
            company=self.company,
            connection_id='gone',
            expires_at=past,
        )
        h = 'x' * 64
        check = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'gone', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h)}',
        )
        self.assertFalse(check.json()['session_allowed'])
