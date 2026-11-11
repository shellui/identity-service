"""Identity → ai-service approval decided notify."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.agents.approval_decisions import approve_pending, deny_pending
from apps.agents.approval_notify import notify_ai_approval_decided, schedule_approval_decided_notify
from apps.agents.models import Agent, McpApprovalRequest, McpOAuthClient
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()


@override_settings(
    AI_SERVICE_URL='https://ai.test',
    JWT_ISSUER='https://identity.test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class ApprovalNotifyTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Notify Co', slug='notify-co')
        self.owner = User.objects.create_user(username='notify-owner', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        client_row = McpOAuthClient.objects.create(client_id='cid-notify', redirect_uris=['http://127.0.0.1/cb'])
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            oauth_client=client_row,
            created_by=self.owner,
            services_allowed=['storage'],
        )

    def _pending_row(self) -> McpApprovalRequest:
        return McpApprovalRequest.objects.create(
            company=self.company,
            agent=self.agent,
            service='storage',
            action='storage_create_bucket',
            arguments_hash='a' * 64,
            status=McpApprovalRequest.STATUS_PENDING,
            expires_at=timezone.now() + timedelta(minutes=10),
        )

    @patch('apps.agents.approval_notify.requests.post')
    def test_notify_posts_assertion_to_ai(self, post):
        post.return_value = MagicMock(status_code=204)
        ok = notify_ai_approval_decided(
            approval_id='appr-1',
            status='approved',
            company_id=self.company.id,
            agent_id=str(self.agent.id),
        )
        self.assertTrue(ok)
        post.assert_called_once()
        args, kwargs = post.call_args
        self.assertEqual(args[0], 'https://ai.test/internal/mcp-approval-decided')
        self.assertEqual(kwargs['json']['approval_id'], 'appr-1')
        self.assertEqual(kwargs['json']['status'], 'approved')
        self.assertTrue(str(kwargs['headers']['Authorization']).startswith('Bearer '))

    @patch('apps.agents.approval_notify.requests.post')
    def test_notify_returns_false_when_ai_unreachable(self, post):
        import requests

        post.side_effect = requests.RequestException('down')
        ok = notify_ai_approval_decided(
            approval_id='appr-1',
            status='denied',
            company_id=self.company.id,
            agent_id=str(self.agent.id),
        )
        self.assertFalse(ok)

    @override_settings(AI_SERVICE_URL='')
    def test_notify_skips_when_ai_url_empty(self):
        self.assertFalse(
            notify_ai_approval_decided(
                approval_id='appr-1',
                status='approved',
                company_id=self.company.id,
                agent_id=str(self.agent.id),
            )
        )

    def test_approve_and_deny_schedule_notify(self):
        with patch('apps.agents.approval_notify.schedule_approval_decided_notify') as schedule:
            row = self._pending_row()
            approve_pending(row, decided_by=self.owner, audit_status='approved')
            schedule.assert_called_once()
            self.assertEqual(schedule.call_args.args[0].status, McpApprovalRequest.STATUS_APPROVED)

        with patch('apps.agents.approval_notify.schedule_approval_decided_notify') as schedule:
            row = self._pending_row()
            deny_pending(row, decided_by=self.owner, audit_status='denied')
            schedule.assert_called_once()
            self.assertEqual(schedule.call_args.args[0].status, McpApprovalRequest.STATUS_REJECTED)

    @patch('apps.agents.approval_notify.notify_ai_approval_decided', side_effect=RuntimeError('ai down'))
    @patch('apps.agents.approval_notify.threading.Thread')
    def test_schedule_runs_notify_in_daemon_thread(self, thread_cls, notify):
        from django.db import transaction

        row = self._pending_row()
        row.status = McpApprovalRequest.STATUS_APPROVED
        row.decided_at = timezone.now()
        thread = MagicMock()
        thread_cls.return_value = thread
        queued = []
        with patch.object(transaction, 'on_commit', side_effect=lambda fn: queued.append(fn)):
            schedule_approval_decided_notify(row)
        self.assertEqual(len(queued), 1)
        queued[0]()
        self.assertTrue(thread_cls.call_args.kwargs.get('daemon'))
        thread.start.assert_called_once()
        # Execute the scheduled target synchronously to prove notify errors stay inside the worker.
        target = thread_cls.call_args.kwargs.get('target') or thread_cls.call_args.args[0]
        target()
        notify.assert_called_once()
