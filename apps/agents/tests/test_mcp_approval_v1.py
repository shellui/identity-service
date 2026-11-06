import json
import time
import uuid
from datetime import timedelta

import jwt
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from shellui_django.mcp.internal import APPROVAL_AUDIENCE, APPROVAL_SCOPE

from apps.actions.models import EventLog
from apps.agents.agent_permissions import bump_agent_grant_version, invalidate_agent_session_grants
from apps.agents.approval_links import sign_approval_fallback_token
from apps.agents.models import Agent, McpApprovalRequest, McpApprovalSessionGrant
from apps.agents.tests.mcp_test_settings import (
    TEST_AI_CALLER_SIGNING,
    TEST_CALLER_SIGNING,
    TRUSTED_AI_TEST_CALLER_SETTINGS,
    TRUSTED_TEST_CALLER_SETTINGS,
    approval_authority_snapshot_for_agent,
    authority_claims_for_agent,
    build_mcp_approval_assertion_for_agent,
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
        self.agent = Agent.objects.create(
            company=self.company,
            name='Writer',
            created_by=self.member,
            services_allowed=['storage'],
        )
        self.other_agent = Agent.objects.create(company=self.company, name='Other', created_by=self.owner)

    def _enable_agent_setup_context(self, agent, *, minutes=20):
        now = timezone.now()
        agent.setup_company_id = self.company.id
        agent.setup_context_expires_at = now + timedelta(minutes=minutes)
        agent.setup_new_company_grant = True
        agent.setup_mcp_session_ttl_seconds = 600
        if agent.global_company_id is None:
            agent.global_company_id = uuid.uuid4()
        if agent.company_binding_version is None:
            agent.company_binding_version = 1
        agent.save(
            update_fields=[
                'setup_company_id',
                'setup_context_expires_at',
                'setup_new_company_grant',
                'setup_mcp_session_ttl_seconds',
                'global_company_id',
                'company_binding_version',
            ]
        )

    def _token(self, user):
        from apps.authapi.views import _issue_shellui_tokens

        return _issue_shellui_tokens(user, company=self.company)['access_token']

    def _assertion(self, agent, *, args_hash='abc123', service='storage', action='write_file'):
        return build_mcp_approval_assertion_for_agent(
            agent,
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
            **authority_claims_for_agent(agent),
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
            **authority_claims_for_agent(agent),
        }
        if extra_claims:
            claims.update(extra_claims)
        token = jwt.encode(claims, signing['private_key_pem'], algorithm='RS256', headers={'kid': signing['kid']})
        return token.decode('utf-8') if isinstance(token, bytes) else token

    def _create_via_internal(self, agent=None, *, args_hash='abc123', **extra_body):
        agent = agent or self.agent
        body = {
            'is_destructive': False,
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

    def _create_via_internal_ai(self, agent=None, *, args_hash='abc123', **extra_body):
        agent = agent or self.agent
        body = {
            'is_destructive': False,
            **extra_body,
        }
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-requests',
            data=json.dumps(body),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._ai_assertion(agent, args_hash=args_hash)}',
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_delegated_agent_rejects_storage_approval_create(self):
        delegated = Agent.objects.create(
            company=self.company,
            name='Delegated',
            created_by=self.member,
            services_allowed=['storage'],
            global_agent_id=uuid.uuid4(),
            global_company_id=uuid.uuid4(),
            company_binding_version=1,
        )
        body = {
            'is_destructive': False,
        }
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-requests',
            data=json.dumps(body),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(delegated, args_hash="deleg" + "a" * 59)}',
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json().get('error_code'), 'out_of_sync')

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

    def test_session_check_returns_live_binding_and_grant_version_for_delegated(self):
        gid = uuid.uuid4()
        self.agent.global_agent_id = uuid.uuid4()
        self.agent.global_company_id = gid
        self.agent.company_binding_version = 0
        self.agent.save(
            update_fields=['global_agent_id', 'global_company_id', 'company_binding_version']
        )
        h = 'e3' * 32
        created = self._create_via_internal_ai(args_hash=h)
        decide_assertion = self._ai_assertion(self.agent, args_hash=h)
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'live-triplet'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {decide_assertion}',
        )
        check_assertion = self._ai_assertion(self.agent, args_hash=h)
        check = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'live-triplet', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {check_assertion}',
        )
        self.assertEqual(check.status_code, 200)
        body = check.json()
        self.assertTrue(body['session_allowed'])
        self.assertEqual(body['grant_version'], int(self.agent.grant_version))
        self.assertEqual(body['global_company_id'], str(gid))
        self.assertEqual(body['company_binding_version'], 0)

    def test_session_check_403_when_delegated_missing_company_binding(self):
        self.agent.global_agent_id = uuid.uuid4()
        self.agent.global_company_id = None
        self.agent.company_binding_version = None
        self.agent.save(update_fields=['global_agent_id', 'global_company_id', 'company_binding_version'])
        h = 'e4' * 32
        created = self._create_via_internal_ai(args_hash=h)
        decide_assertion = self._ai_assertion(self.agent, args_hash=h)
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'no-bind'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {decide_assertion}',
        )
        check_assertion = self._ai_assertion(self.agent, args_hash=h)
        check = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'no-bind', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {check_assertion}',
        )
        self.assertEqual(check.status_code, 403)
        self.assertFalse(check.json().get('session_allowed', True))

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
        self.assertEqual(grant.service, 'storage')
        self.assertEqual(grant.action, 'write_file')
        self.assertEqual(grant.arguments_hash, 'e' * 64)
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

    def test_internal_approval_create_rejects_arguments_redacted(self):
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-requests',
            data=json.dumps({'is_destructive': False, 'arguments_redacted': {}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash="x" * 64)}',
        )
        self.assertEqual(response.status_code, 400)

    def test_internal_approval_create_rejects_arguments_key(self):
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-requests',
            data=json.dumps({'is_destructive': False, 'arguments': {}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash="x" * 64)}',
        )
        self.assertEqual(response.status_code, 400)

    def test_internal_approval_create_requires_json_bool_is_destructive(self):
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-requests',
            data=json.dumps({'is_destructive': 'false'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash="y" * 64)}',
        )
        self.assertEqual(response.status_code, 400)

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
            **approval_authority_snapshot_for_agent(self.agent),
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
            **approval_authority_snapshot_for_agent(self.agent),
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
            **approval_authority_snapshot_for_agent(self.agent),
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

    def test_session_check_setup_echo_reflects_grant_snapshot_not_extended_agent(self):
        """After Allow session, inflated agent setup must not change the check payload."""
        h = 'snap-setup' + 'y' * 52
        self._enable_agent_setup_context(self.agent, minutes=20)
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
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'snap-ctx'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        now = timezone.now()
        self.agent.setup_context_expires_at = now + timedelta(hours=2)
        self.agent.setup_mcp_session_ttl_seconds = 900
        self.agent.save(update_fields=['setup_context_expires_at', 'setup_mcp_session_ttl_seconds'])
        chk = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'snap-ctx', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h)}',
        )
        self.assertEqual(chk.status_code, 200)
        body = chk.json()
        self.assertTrue(body['session_allowed'])
        grant = McpApprovalSessionGrant.objects.get(agent=self.agent, connection_id='snap-ctx')
        self.assertEqual(body['setup_expires_at'], int(grant.setup_context_expires_at.timestamp()))
        self.assertEqual(body['mcp_session_ttl_seconds'], grant.setup_mcp_session_ttl_seconds)

    def test_setup_session_uses_600_seconds_when_ai_mints_setup_claims(self):
        h = 's' * 64
        self._enable_agent_setup_context(self.agent)
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
            lifetime_seconds=60,
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

    def test_setup_without_agent_context_falls_back_to_default(self):
        h = 's2' * 32
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
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'no-ctx'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        grant = McpApprovalSessionGrant.objects.get(agent=self.agent, connection_id='no-ctx')
        self.assertAlmostEqual((grant.expires_at - timezone.now()).total_seconds(), 60, delta=5)

    def test_setup_ttl_falls_back_when_remaining_under_band(self):
        """Under 600s left to setup deadline (or JWT), extended setup band is not used."""
        h = 's3' * 32
        self._enable_agent_setup_context(self.agent, minutes=5)
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
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'cap-ctx'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        grant = McpApprovalSessionGrant.objects.get(agent=self.agent, connection_id='cap-ctx')
        self.assertAlmostEqual((grant.expires_at - timezone.now()).total_seconds(), 60, delta=5)

    def test_setup_ttl_respects_ceiling_when_both_remaining_exceed_band(self):
        h = 's3b' * 20 + 'aa'
        self._enable_agent_setup_context(self.agent, minutes=30)
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
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'cap-ceil'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        grant = McpApprovalSessionGrant.objects.get(agent=self.agent, connection_id='cap-ceil')
        self.assertAlmostEqual((grant.expires_at - timezone.now()).total_seconds(), 600, delta=10)

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

    def test_allow_session_on_expired_approval_leaves_no_grant(self):
        h = 'exp' + 'a' * 61
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_file',
            arguments_hash=h,
            short_action_summary='x',
            expires_at=timezone.now() - timedelta(seconds=1),
            status=McpApprovalRequest.STATUS_PENDING,
            **approval_authority_snapshot_for_agent(self.agent),
        )
        assertion = self._assertion(self.agent, args_hash=h)
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': str(row.id), 'decision': 'allow_session', 'connection_id': 'exp-appr'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        self.assertEqual(response.status_code, 409)
        self.assertFalse(
            McpApprovalSessionGrant.objects.filter(agent=self.agent, connection_id='exp-appr').exists()
        )

    def test_allow_session_second_decision_rejected_no_extra_grant(self):
        h = 'r1' + 'b' * 62
        created = self._create_via_internal(args_hash=h)
        assertion1 = self._assertion(self.agent, args_hash=h)
        first = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'replay'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion1}',
        )
        self.assertEqual(first.status_code, 200)
        assertion2 = self._assertion(self.agent, args_hash=h)
        second = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'replay'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion2}',
        )
        self.assertEqual(second.status_code, 409)
        self.assertEqual(
            McpApprovalSessionGrant.objects.filter(agent=self.agent, connection_id='replay').count(),
            1,
        )

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

    def test_session_check_rejects_stale_assertion_authority(self):
        """``mcp-approval-session-check`` uses live authority like other internal routes."""
        h = 'auth-stale' + 'q' * 50
        created = self._create_via_internal(args_hash=h)
        decide_assertion = self._assertion(self.agent, args_hash=h)
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'auth-snap'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {decide_assertion}',
        )
        bump_agent_grant_version(self.agent)
        self.agent.refresh_from_db()
        bad = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'auth-snap', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {build_mcp_approval_assertion_for_agent(self.agent, **TEST_CALLER_SIGNING, company_id=self.company.id, agent_id=str(self.agent.id), service="storage", action="write_file", arguments_hash=h, audience_url="https://identity.test", authority_claims_override={"grant_version": 0})}',
        )
        self.assertEqual(bad.status_code, 409)
        self.assertEqual(bad.json()['error'], 'Approval authority mismatch.')

    def test_session_invalid_when_grant_version_changes_after_allow_session(self):
        """``grant_version`` invalidates existing session grants (stricter than the default TTL)."""
        h = 'survive-gv' + 'z' * 52
        created = self._create_via_internal(args_hash=h)
        decide_assertion = self._assertion(self.agent, args_hash=h)
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'gv-survive'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {decide_assertion}',
        )
        bump_agent_grant_version(self.agent)
        self.agent.refresh_from_db()
        check_assertion = self._assertion(self.agent, args_hash=h)
        ok = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'gv-survive', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {check_assertion}',
        )
        self.assertEqual(ok.status_code, 200)
        self.assertFalse(ok.json()['session_allowed'])

    def test_session_invalid_after_permission_invalidation(self):
        h = 'pv' * 32
        created = self._create_via_internal(args_hash=h)
        # Fresh assertion per request: internal assertions are single-use (jti).
        decide_assertion = self._assertion(self.agent, args_hash=h)
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'perm-ver'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {decide_assertion}',
        )
        ok = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'perm-ver', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h)}',
        )
        self.assertTrue(ok.json()['session_allowed'])
        invalidate_agent_session_grants(self.agent)
        self.agent.refresh_from_db()
        bad = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'perm-ver', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h)}',
        )
        self.assertFalse(bad.json()['session_allowed'])

    def test_internal_routes_reject_stale_authority_after_agent_narrowed(self):
        """Pending human approval must fail closed after grant_version bumps; in-flight unchanged still works."""
        h = 'st' * 32
        created = self._create_via_internal(args_hash=h)
        approval_id = created['id']
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.grant_version, 0)
        bump_agent_grant_version(self.agent)
        self.agent.refresh_from_db()
        state = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-state',
            data=json.dumps({}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h)}',
        )
        self.assertEqual(state.status_code, 409)
        self.assertEqual(state.json()['error'], 'Approval authority stale.')

        decide = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps({'approval_id': approval_id, 'decision': 'allow'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h)}',
        )
        self.assertEqual(decide.status_code, 409)
        self.assertEqual(decide.json()['error'], 'Approval authority stale.')

        token = self._token(self.member)
        approved = self.client.post(
            f'/api/v1/mcp/approvals/{approval_id}/decide',
            data=json.dumps({'decision': 'approve'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(approved.status_code, 200)

        consume = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-consume',
            data=json.dumps({'approval_id': approval_id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h)}',
        )
        self.assertEqual(consume.status_code, 409)
        self.assertFalse(consume.json().get('consumed', True))

        fresh = self._create_via_internal(args_hash=h + 'x')
        ok_state = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-state',
            data=json.dumps({}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h + "x")}',
        )
        self.assertEqual(ok_state.status_code, 200)
        self.assertEqual(ok_state.json()['status'], 'pending')
        decide_fresh = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps({'approval_id': fresh['id'], 'decision': 'allow'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h + "x")}',
        )
        self.assertEqual(decide_fresh.status_code, 200)

    def test_session_invalid_when_company_binding_version_advances(self):
        """Binding bumps invalidate the grant snapshot vs the current agent."""
        h = 'cb' * 32
        gid = uuid.uuid4()
        self.agent.global_company_id = gid
        self.agent.company_binding_version = 1
        self.agent.save(update_fields=['global_company_id', 'company_binding_version'])
        created = self._create_via_internal(args_hash=h)
        decide_assertion = self._assertion(self.agent, args_hash=h)
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'bind'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {decide_assertion}',
        )
        self.agent.company_binding_version = 2
        self.agent.save(update_fields=['company_binding_version'])
        check = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'bind', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h)}',
        )
        self.assertEqual(check.status_code, 200)
        self.assertFalse(check.json()['session_allowed'])

    def test_session_invalid_when_services_allowed_changes(self):
        h = 'svc' * 20 + 'aa'
        created = self._create_via_internal(args_hash=h)
        decide_assertion = self._assertion(self.agent, args_hash=h)
        self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(
                {'approval_id': created['id'], 'decision': 'allow_session', 'connection_id': 'svc-ch'}
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {decide_assertion}',
        )
        self.agent.services_allowed = ['identity']
        self.agent.save(update_fields=['services_allowed'])
        self.agent.refresh_from_db()
        check = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-session-check',
            data=json.dumps({'connection_id': 'svc-ch', 'is_destructive': False}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(self.agent, args_hash=h)}',
        )
        self.assertFalse(check.json()['session_allowed'])
