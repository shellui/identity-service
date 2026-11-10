"""In-chat consent on the internal MCP approval decide route."""

from __future__ import annotations

import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.actions.models import EventLog
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
class McpApprovalConsentTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-approval-consent')
        self.owner = User.objects.create_user(username='consent-owner', email='owner@acme.com', password='unused')
        self.member = User.objects.create_user(username='consent-member', email='member@acme.com', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.member, enabled=True)
        self.agent = Agent.objects.create(
            company=self.company,
            name='Writer',
            created_by=self.member,
            services_allowed=['storage'],
        )

    def _assertion(self, *, args_hash: str):
        return build_mcp_approval_assertion_for_agent(
            self.agent,
            **TEST_CALLER_SIGNING,
            company_id=self.company.id,
            agent_id=str(self.agent.id),
            service='storage',
            action='write_file',
            arguments_hash=args_hash,
            audience_url='https://identity.test',
        )

    def _row(self, *, args_hash: str, destructive: bool = False) -> McpApprovalRequest:
        return McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='write_file',
            arguments_hash=args_hash,
            is_destructive=destructive,
            expires_at=timezone.now() + timedelta(minutes=10),
            **approval_authority_snapshot_for_agent(self.agent),
        )

    def _decide(self, row: McpApprovalRequest, body: dict):
        payload = {'approval_id': str(row.id), **body}
        return self.client.post(
            '/api/v1/mcp/internal/mcp-approval-decide',
            data=json.dumps(payload),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(args_hash=row.arguments_hash)}',
        )

    def _owner_token(self) -> str:
        from apps.authapi.views import _issue_shellui_tokens

        return _issue_shellui_tokens(self.owner, company=self.company)['access_token']

    def test_allow_stores_in_chat_consent_and_client_name(self):
        row = self._row(args_hash='a' * 64)
        response = self._decide(
            row,
            {
                'decision': 'allow',
                'actor_email': 'member@acme.com',
                'consent': 'in_chat',
                'client_name': '  Claude\nDesktop  ',
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json(),
            {
                'approval_id': str(row.id),
                'status': 'approved',
                'audit_status': 'client_allowed',
                'consent': 'in_chat',
                'client_name': 'Claude Desktop',
            },
        )
        row.refresh_from_db()
        self.assertEqual(row.consent, McpApprovalRequest.CONSENT_IN_CHAT)
        self.assertEqual(row.client_name, 'Claude Desktop')
        event = EventLog.objects.filter(event_type='identity.mcp.approval_decision').latest('id')
        self.assertEqual(event.data['status'], 'client_allowed')
        self.assertEqual(event.data['consent'], 'in_chat')
        self.assertEqual(event.data['client_name'], 'Claude Desktop')
        self.assertEqual(event.data['approval_id'], str(row.id))

        token = self._owner_token()
        detail = self.client.get(
            f'/api/v1/mcp/approvals/{row.id}',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(detail.status_code, 200, detail.content)
        approval = detail.json()['approval']
        self.assertEqual(approval['consent'], 'in_chat')
        self.assertEqual(approval['client_name'], 'Claude Desktop')

        history = self.client.get(
            '/api/v1/events?event_type=identity.mcp.approval_decision',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(history.status_code, 200, history.content)
        match = next(item for item in history.json()['results'] if item['data'].get('approval_id') == str(row.id))
        self.assertEqual(match['data']['consent'], 'in_chat')
        self.assertEqual(match['data']['client_name'], 'Claude Desktop')

    def test_omitted_consent_keeps_the_previous_response_shape(self):
        row = self._row(args_hash='b' * 64)
        response = self._decide(row, {'decision': 'allow'})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            set(response.json()),
            {'approval_id', 'status', 'audit_status'},
        )
        row.refresh_from_db()
        self.assertEqual(row.consent, '')
        self.assertEqual(row.client_name, '')
        event = EventLog.objects.filter(event_type='identity.mcp.approval_decision').latest('id')
        self.assertNotIn('consent', event.data)
        self.assertNotIn('client_name', event.data)
        detail = self.client.get(
            f'/api/v1/mcp/approvals/{row.id}',
            HTTP_AUTHORIZATION=f'Bearer {self._owner_token()}',
        )
        self.assertNotIn('consent', detail.json()['approval'])
        self.assertNotIn('client_name', detail.json()['approval'])

    def test_in_chat_consent_rejects_a_destructive_tool(self):
        row = self._row(args_hash='c' * 64, destructive=True)
        response = self._decide(row, {'decision': 'allow', 'consent': 'in_chat', 'client_name': 'Claude'})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['error'], 'In-chat consent is not allowed for a destructive tool.')
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_PENDING)
        self.assertEqual(row.consent, '')
        self.assertFalse(
            EventLog.objects.filter(event_type='identity.mcp.approval_decision', data__approval_id=str(row.id)).exists()
        )

    def test_link_consent_allows_a_destructive_tool(self):
        row = self._row(args_hash='d' * 64, destructive=True)
        response = self._decide(row, {'decision': 'allow', 'consent': 'link', 'client_name': 'Inspector'})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()['consent'], 'link')
        self.assertEqual(response.json()['client_name'], 'Inspector')
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_APPROVED)
        self.assertEqual(row.consent, McpApprovalRequest.CONSENT_LINK)

    def test_consent_and_client_name_are_strict(self):
        row = self._row(args_hash='e' * 64)
        bad_consent = self._decide(row, {'decision': 'allow', 'consent': 'email'})
        self.assertEqual(bad_consent.status_code, 400)
        not_string = self._decide(row, {'decision': 'allow', 'consent': True})
        self.assertEqual(not_string.status_code, 400)
        too_long = self._decide(row, {'decision': 'allow', 'client_name': 'x' * 81})
        self.assertEqual(too_long.status_code, 400)
        nested = self._decide(row, {'decision': 'allow', 'client_name': {'name': 'Claude'}})
        self.assertEqual(nested.status_code, 400)
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_PENDING)

    def test_session_allow_stores_in_chat_consent(self):
        row = self._row(args_hash='f' * 64)
        response = self._decide(
            row,
            {
                'decision': 'allow_session',
                'connection_id': 'conn-chat',
                'consent': 'in_chat',
                'client_name': 'Grok',
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()['audit_status'], 'client_session_allowed')
        self.assertEqual(response.json()['consent'], 'in_chat')
        row.refresh_from_db()
        self.assertEqual(row.client_name, 'Grok')
        event = EventLog.objects.filter(event_type='identity.mcp.approval_decision').latest('id')
        self.assertEqual(event.data['status'], 'client_session_allowed')
        self.assertEqual(event.data['consent'], 'in_chat')
        self.assertEqual(event.data['client_name'], 'Grok')
