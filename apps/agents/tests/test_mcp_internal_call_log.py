"""Internal MCP call log ingest (signed assertions, strict path and body rules)."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta

import jwt
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from shellui_django.mcp.internal import CALL_LOG_AUDIENCE, CALL_LOG_SCOPE, build_mcp_call_log_assertion

from apps.agents.models import Agent, McpApprovalRequest
from apps.agents.tests.mcp_test_settings import (
    TEST_CALLER_SIGNING,
    TRUSTED_TEST_CALLER_SETTINGS,
    approval_authority_snapshot_for_agent,
)

User = get_user_model()

_PATH = '/api/v1/mcp/internal/mcp-call-logs'


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    STORAGE_SERVICE_URL='https://storage.region.example',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpInternalCallLogTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company = __import__('apps.companies.models', fromlist=['Company']).Company.objects.create(
            name='LogCo', slug='log-co'
        )
        self.user = User.objects.create_user(username='u1', email='u@log.co', password='unused')
        self.company.owners.add(self.user)
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            created_by=self.user,
            services_allowed=['storage'],
        )

    def _assertion(self):
        return build_mcp_call_log_assertion(
            audience_url='https://identity.test',
            private_key_pem=TEST_CALLER_SIGNING['private_key_pem'],
            kid=TEST_CALLER_SIGNING['kid'],
            issuer=TEST_CALLER_SIGNING['issuer'],
        )

    def _post(self, body: dict):
        base = {'grant_version': 0}
        base.update(body)
        return self.client.post(
            _PATH,
            data=json.dumps(base),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion()}',
        )

    def test_accepts_strict_mcp_path(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 12,
                'access_kind': 'read',
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 201, r.content)
        from apps.agents.models import McpCallLog

        log = McpCallLog.objects.get(pk=r.json()['id'])
        self.assertEqual(log.resource_label, 'POST /mcp (storage)')

    def test_empty_path_normalized_to_mcp(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 201)

    def test_rejects_arguments_payload(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'x',
                'arguments': {'a': 1},
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 400)

    def test_rejects_untrusted_path(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/users/1',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 400)

    def test_outcome_required(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
            }
        )
        self.assertEqual(r.status_code, 400)

    def test_rejects_non_int_company_id(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': True,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
            }
        )
        self.assertEqual(r.status_code, 400)

    def test_rejects_invalid_outcome(self):
        r = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'not_a_real_outcome',
            }
        )
        self.assertEqual(r.status_code, 400)

    def test_approval_id_requires_matching_action(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='list_buckets',
            arguments_hash='a' * 64,
            short_action_summary='x',
            expires_at=timezone.now() + __import__('datetime').timedelta(minutes=5),
            status=McpApprovalRequest.STATUS_APPROVED,
            **approval_authority_snapshot_for_agent(self.agent),
        )
        r_ok = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'approval_id': str(row.id),
            }
        )
        self.assertEqual(r_ok.status_code, 201)
        body = __import__('json').loads(r_ok.content.decode())
        from apps.agents.models import McpCallLog

        log = McpCallLog.objects.get(pk=body['id'])
        self.assertEqual(log.approval_id, row.id)

        r_bad = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'other_tool',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'approval_id': str(row.id),
            }
        )
        self.assertEqual(r_bad.status_code, 400, r_bad.content)

    def test_delegated_requires_binding_triplet(self):
        import uuid as uuid_mod

        gc = uuid_mod.uuid4()
        self.agent.global_agent_id = uuid_mod.uuid4()
        self.agent.global_company_id = gc
        self.agent.company_binding_version = 2
        self.agent.grant_version = 5
        self.agent.save(
            update_fields=[
                'global_agent_id',
                'global_company_id',
                'company_binding_version',
                'grant_version',
            ]
        )
        r_ok = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'grant_version': 5,
                'global_company_id': str(gc),
                'company_binding_version': 2,
            }
        )
        self.assertEqual(r_ok.status_code, 201, r_ok.content)
        r_conflict = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'list_buckets',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'grant_version': 5,
                'global_company_id': str(uuid_mod.uuid4()),
                'company_binding_version': 2,
            }
        )
        self.assertEqual(r_conflict.status_code, 409, r_conflict.content)

    def test_destructive_requires_approved_destructive_approval(self):
        self.agent.global_max_destructive = True
        self.agent.save(update_fields=['global_max_destructive'])
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='wipe_bucket',
            arguments_hash='b' * 64,
            short_action_summary='x',
            expires_at=timezone.now() + __import__('datetime').timedelta(minutes=5),
            status=McpApprovalRequest.STATUS_APPROVED,
            is_destructive=True,
            **approval_authority_snapshot_for_agent(self.agent),
        )
        r_ok = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'wipe_bucket',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'access_kind': 'destructive',
                'approval_id': str(row.id),
            }
        )
        self.assertEqual(r_ok.status_code, 201, r_ok.content)
        r_no_appr = self._post(
            {
                'agent_id': str(self.agent.id),
                'company_id': self.company.pk,
                'service': 'storage',
                'tool': 'wipe_bucket',
                'method': 'POST',
                'path': '/mcp',
                'status': 200,
                'duration_ms': 1,
                'outcome': 'allowed',
                'access_kind': 'destructive',
            }
        )
        self.assertEqual(r_no_appr.status_code, 400, r_no_appr.content)

    def _enable_destructive(self):
        self.agent.global_max_destructive = True
        self.agent.save(update_fields=['global_max_destructive'])

    def _destructive_approval(self, *, status, action='wipe_bucket', arguments_hash='b' * 64, **extra):
        self._enable_destructive()
        fields = {
            'agent': self.agent,
            'company': self.company,
            'service': 'storage',
            'action': action,
            'arguments_hash': arguments_hash,
            'short_action_summary': 'x',
            'expires_at': timezone.now() + timedelta(minutes=5),
            'status': status,
            'is_destructive': True,
            **approval_authority_snapshot_for_agent(self.agent),
        }
        fields.update(extra)
        return McpApprovalRequest.objects.create(**fields)

    def _destructive_body(self, *, outcome, approval=None, tool='wipe_bucket'):
        body = {
            'agent_id': str(self.agent.id),
            'company_id': self.company.pk,
            'service': 'storage',
            'tool': tool,
            'method': 'POST',
            'path': '/mcp',
            'status': 200,
            'duration_ms': 1,
            'outcome': outcome,
            'access_kind': 'destructive',
        }
        if approval is not None:
            body['approval_id'] = str(approval.id)
        return body

    def test_destructive_allowed_and_failed_for_approved_or_executed(self):
        from apps.agents.models import McpCallLog

        approved = self._destructive_approval(status=McpApprovalRequest.STATUS_APPROVED, arguments_hash='c' * 64)
        executed = self._destructive_approval(status=McpApprovalRequest.STATUS_EXECUTED, arguments_hash='d' * 64)
        for row, outcome in (
            (approved, 'allowed'),
            (approved, 'failed'),
            (executed, 'allowed'),
            (executed, 'failed'),
        ):
            response = self._post(self._destructive_body(outcome=outcome, approval=row))
            self.assertEqual(response.status_code, 201, response.content)
            log = McpCallLog.objects.get(pk=response.json()['id'])
            self.assertEqual(log.approval_id, row.id)
            self.assertEqual(log.access_kind, 'destructive')
            self.assertEqual(log.outcome, outcome)
            self.assertEqual(log.arguments_redacted, {})
            self.assertNotIn('arguments', response.json())
        approved.refresh_from_db()
        executed.refresh_from_db()
        self.assertEqual(approved.status, McpApprovalRequest.STATUS_APPROVED)
        self.assertEqual(executed.status, McpApprovalRequest.STATUS_EXECUTED)

    def test_destructive_denied_and_waiting_stay_destructive(self):
        from apps.agents.models import McpCallLog

        pending = self._destructive_approval(status=McpApprovalRequest.STATUS_PENDING, arguments_hash='e' * 64)
        rejected = self._destructive_approval(status=McpApprovalRequest.STATUS_REJECTED, arguments_hash='f' * 64)
        executed = self._destructive_approval(status=McpApprovalRequest.STATUS_EXECUTED, arguments_hash='1' * 64)
        approved = self._destructive_approval(status=McpApprovalRequest.STATUS_APPROVED, arguments_hash='2' * 64)

        denied = self._post(self._destructive_body(outcome='denied'))
        self.assertEqual(denied.status_code, 201, denied.content)
        denied_log = McpCallLog.objects.get(pk=denied.json()['id'])
        self.assertEqual(denied_log.access_kind, 'destructive')
        self.assertEqual(denied_log.outcome, 'denied')
        self.assertIsNone(denied_log.approval_id)

        waiting = self._post(self._destructive_body(outcome='waiting_approval'))
        self.assertEqual(waiting.status_code, 201, waiting.content)
        waiting_log = McpCallLog.objects.get(pk=waiting.json()['id'])
        self.assertEqual(waiting_log.access_kind, 'destructive')
        self.assertEqual(waiting_log.outcome, 'waiting_approval')
        self.assertNotEqual(waiting_log.access_kind, 'write')

        linked_denied = self._post(self._destructive_body(outcome='denied', approval=pending))
        self.assertEqual(linked_denied.status_code, 201, linked_denied.content)
        self.assertEqual(McpCallLog.objects.get(pk=linked_denied.json()['id']).approval_id, pending.id)

        linked_waiting = self._post(self._destructive_body(outcome='waiting_approval', approval=rejected))
        self.assertEqual(linked_waiting.status_code, 201, linked_waiting.content)
        self.assertEqual(McpCallLog.objects.get(pk=linked_waiting.json()['id']).approval_id, rejected.id)

        denied_executed = self._post(self._destructive_body(outcome='denied', approval=executed))
        self.assertEqual(denied_executed.status_code, 400, denied_executed.content)
        waiting_approved = self._post(self._destructive_body(outcome='waiting_approval', approval=approved))
        self.assertEqual(waiting_approved.status_code, 400, waiting_approved.content)

        pending.refresh_from_db()
        rejected.refresh_from_db()
        executed.refresh_from_db()
        approved.refresh_from_db()
        self.assertEqual(pending.status, McpApprovalRequest.STATUS_PENDING)
        self.assertEqual(rejected.status, McpApprovalRequest.STATUS_REJECTED)
        self.assertEqual(executed.status, McpApprovalRequest.STATUS_EXECUTED)
        self.assertEqual(approved.status, McpApprovalRequest.STATUS_APPROVED)

    def test_destructive_session_used_rejected(self):
        approved = self._destructive_approval(status=McpApprovalRequest.STATUS_APPROVED, arguments_hash='3' * 64)
        response = self._post(self._destructive_body(outcome='session_used', approval=approved))
        self.assertEqual(response.status_code, 400, response.content)
        approved.refresh_from_db()
        self.assertEqual(approved.status, McpApprovalRequest.STATUS_APPROVED)

    def test_destructive_preserves_requested_approval_id(self):
        from apps.agents.models import McpCallLog

        first = self._destructive_approval(status=McpApprovalRequest.STATUS_EXECUTED, arguments_hash='4' * 64)
        second = self._destructive_approval(status=McpApprovalRequest.STATUS_EXECUTED, arguments_hash='5' * 64)
        response = self._post(self._destructive_body(outcome='failed', approval=second))
        self.assertEqual(response.status_code, 201, response.content)
        log = McpCallLog.objects.get(pk=response.json()['id'])
        self.assertEqual(log.approval_id, second.id)
        self.assertNotEqual(log.approval_id, first.id)
        self.assertEqual(log.arguments_redacted, {})
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(first.status, McpApprovalRequest.STATUS_EXECUTED)
        self.assertEqual(second.status, McpApprovalRequest.STATUS_EXECUTED)

    def test_destructive_ambiguous_fingerprint_rejected(self):
        from apps.agents.models import McpCallLog

        match = self._destructive_approval(status=McpApprovalRequest.STATUS_EXECUTED, arguments_hash='6' * 64)
        other = self._destructive_approval(
            status=McpApprovalRequest.STATUS_EXECUTED,
            arguments_hash='7' * 64,
            authority_grant_version=99,
        )
        rejected = self._post(self._destructive_body(outcome='allowed', approval=other))
        self.assertEqual(rejected.status_code, 400, rejected.content)
        self.assertFalse(McpCallLog.objects.filter(approval_id=other.id).exists())
        self.assertFalse(McpCallLog.objects.filter(approval_id=match.id).exists())
        accepted = self._post(self._destructive_body(outcome='failed', approval=match))
        self.assertEqual(accepted.status_code, 201, accepted.content)
        self.assertEqual(McpCallLog.objects.get(pk=accepted.json()['id']).approval_id, match.id)
        match.refresh_from_db()
        self.assertEqual(match.status, McpApprovalRequest.STATUS_EXECUTED)
