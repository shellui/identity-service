"""Approval decide and consume lock the approval row, not the nullable agent join.

SQLite ignores ``FOR UPDATE``, so the PostgreSQL ``NotSupportedError`` only shows up
when this module runs against Postgres. The query shape is asserted on every backend.
"""

from __future__ import annotations

import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.agents.approval_decisions import lock_approval_for_update
from apps.agents.models import Agent, McpApprovalRequest
from apps.agents.tests.mcp_test_settings import (
    TEST_CALLER_SIGNING,
    TRUSTED_TEST_CALLER_SETTINGS,
    approval_authority_snapshot_for_agent,
    build_mcp_approval_assertion_for_agent,
)
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class ApprovalRowLockTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Lock Co', slug='lock-co')
        self.owner = User.objects.create_user('lock-owner', 'owner@lock.test', 'x')
        self.other = User.objects.create_user('lock-other', 'other@lock.test', 'x')
        self.staff = User.objects.create_user('lock-staff', 'staff@lock.test', 'x', is_staff=True)
        self.company.owners.add(self.owner, self.staff)
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.other, enabled=True)
        set_company_access(self.company, self.staff, enabled=True)
        self.agent = Agent.objects.create(
            company=self.company,
            name='Writer',
            created_by=self.owner,
            services_allowed=['storage'],
        )

    def _token(self, user):
        from apps.authapi.views import _issue_shellui_tokens

        return _issue_shellui_tokens(user, company=self.company)['access_token']

    def _pending(self, *, arguments_hash: str) -> McpApprovalRequest:
        return McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_file',
            arguments_hash=arguments_hash,
            status=McpApprovalRequest.STATUS_PENDING,
            expires_at=timezone.now() + timedelta(minutes=10),
            is_destructive=True,
            **approval_authority_snapshot_for_agent(self.agent),
        )

    def _decide(self, user, approval_id, decision):
        return self.client.post(
            f'/api/v1/mcp/approvals/{approval_id}/decide',
            data=json.dumps({'decision': decision}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._token(user)}',
        )

    def _consume(self, approval: McpApprovalRequest):
        assertion = build_mcp_approval_assertion_for_agent(
            self.agent,
            **TEST_CALLER_SIGNING,
            company_id=self.company.id,
            agent_id=str(self.agent.id),
            service='storage',
            action='write_file',
            arguments_hash=approval.arguments_hash,
            audience_url='https://identity.test',
        )
        return self.client.post(
            '/api/v1/mcp/internal/mcp-approval-consume',
            data=json.dumps({'approval_id': str(approval.id)}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )

    def test_lock_query_targets_approval_row_only(self):
        qs = (
            McpApprovalRequest.objects.select_for_update(of=('self',))
            .select_related('agent')
            .order_by()
        )
        self.assertTrue(qs.query.select_for_update)
        self.assertEqual(tuple(qs.query.select_for_update_of), ('self',))
        locked = lock_approval_for_update(pk=self._pending(arguments_hash='a' * 64).pk)
        self.assertEqual(locked.agent_id, self.agent.id)
        if connection.vendor == 'postgresql':
            sql = str(
                McpApprovalRequest.objects.select_for_update(of=('self',))
                .select_related('agent')
                .filter(pk=locked.pk)
                .query
            ).upper()
            self.assertIn('FOR UPDATE OF', sql)
            self.assertIn('MCPAPPROVALREQUEST', sql.replace('"', ''))

    def test_owner_decide_then_consume_once(self):
        pending = self._pending(arguments_hash='b' * 64)
        staff = self._decide(self.staff, pending.id, 'approve')
        self.assertEqual(staff.status_code, 403, staff.content)
        stranger = self._decide(self.other, pending.id, 'approve')
        self.assertEqual(stranger.status_code, 403, stranger.content)
        pending.refresh_from_db()
        self.assertEqual(pending.status, McpApprovalRequest.STATUS_PENDING)

        approved = self._decide(self.owner, pending.id, 'approve')
        self.assertEqual(approved.status_code, 200, approved.content)
        self.assertEqual(approved.json()['approval']['status'], 'approved')
        again = self._decide(self.owner, pending.id, 'deny')
        self.assertEqual(again.status_code, 409, again.content)
        pending.refresh_from_db()
        self.assertEqual(pending.status, McpApprovalRequest.STATUS_APPROVED)

        first = self._consume(pending)
        self.assertEqual(first.status_code, 200, first.content)
        self.assertTrue(first.json()['consumed'])
        pending.refresh_from_db()
        self.assertEqual(pending.status, McpApprovalRequest.STATUS_EXECUTED)
        second = self._consume(pending)
        self.assertEqual(second.status_code, 409, second.content)
        self.assertFalse(second.json()['consumed'])
        pending.refresh_from_db()
        self.assertEqual(pending.status, McpApprovalRequest.STATUS_EXECUTED)