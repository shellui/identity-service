"""Browser approval page and the approval_url returned to ai-service."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from urllib.parse import urlsplit

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.actions.models import EventLog
from apps.agents.approval_links import sign_approval_fallback_token
from apps.agents.models import Agent, McpApprovalRequest, McpOAuthClient
from apps.agents.tests.mcp_test_settings import (
    TEST_CALLER_SIGNING,
    TRUSTED_TEST_CALLER_SETTINGS,
    approval_authority_snapshot_for_agent,
    build_mcp_approval_assertion_for_agent,
)
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthClient

User = get_user_model()


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpApprovalPageTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-approval-page')
        self.owner = User.objects.create_user(username='page-owner', email='owner@acme.com', password='unused')
        self.member = User.objects.create_user(username='page-member', email='member@acme.com', password='unused')
        self.other = User.objects.create_user(username='page-other', email='other@acme.com', password='unused')
        self.staff = User.objects.create_user(
            username='page-staff',
            email='staff@acme.com',
            password='unused',
            is_staff=True,
        )
        self.company.owners.add(self.owner, self.staff)
        for user in (self.owner, self.member, self.other, self.staff):
            set_company_access(self.company, user, enabled=True)
        self.client_row = McpOAuthClient.objects.create(client_id='chatgpt-page', client_name='ChatGPT')
        self.agent = Agent.objects.create(
            company=self.company,
            name='Writer',
            created_by=self.member,
            oauth_client=self.client_row,
            services_allowed=['storage'],
        )

    def _row(self, **extra):
        fields = {
            'agent': self.agent,
            'company': self.company,
            'service': 'storage',
            'action': 'write_file',
            'arguments_hash': uuid.uuid4().hex,
            'short_action_summary': 'Create notes.txt in Marketing',
            'expires_at': timezone.now() + timedelta(minutes=10),
            **approval_authority_snapshot_for_agent(self.agent),
        }
        fields.update(extra)
        return McpApprovalRequest.objects.create(**fields)

    def _url(self, row: McpApprovalRequest) -> str:
        token = sign_approval_fallback_token(str(row.id))
        return f'/oauth/mcp/approval/{row.id}?token={token}'

    def _open(self, client: Client, row: McpApprovalRequest, **extra):
        url = self._url(row)
        token = url.split('token=', 1)[1]
        page = client.get(url, **extra)
        return url, token, page

    def test_signed_in_member_sees_the_request_and_can_approve(self):
        row = self._row(is_destructive=True)
        client = Client()
        client.force_login(self.member)
        url, token, page = self._open(client, row)
        self.assertContains(page, 'Approve this action?')
        self.assertContains(page, 'Signed in as member@acme.com')
        self.assertContains(page, 'Use another account')
        self.assertContains(page, 'Writer wants to run write_file on Acme')
        self.assertContains(page, 'Acme')
        self.assertContains(page, 'Writer')
        self.assertContains(page, 'ChatGPT')
        self.assertContains(page, 'storage')
        self.assertContains(page, 'write_file')
        self.assertContains(page, 'Create notes.txt in Marketing')
        self.assertContains(page, 'This can change or delete data in Acme.')
        self.assertContains(page, 'UTC')
        self.assertContains(page, 'Approve')
        self.assertContains(page, 'Deny')
        approved = client.post(url, {'decision': 'approve', 'token': token})
        self.assertContains(approved, 'Approved')
        self.assertContains(approved, 'You approved this action.')
        self.assertContains(approved, 'will keep working')
        self.assertNotContains(approved, 'name="decision"')
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_APPROVED)
        self.assertEqual(row.decided_by_id, self.member.pk)

    def test_signed_in_member_can_switch_account_from_approval_page(self):
        row = self._row()
        client = Client()
        client.force_login(self.member)
        url = self._url(row)
        page = client.get(url)
        self.assertContains(page, 'Signed in as member@acme.com')
        self.assertContains(page, 'Use another account')
        switched = client.post(
            url,
            {'account_choice': 'switch', 'token': url.split('token=', 1)[1]},
        )
        self.assertRedirects(switched, '/oauth/mcp/signin', fetch_redirect_response=False)
        self.assertNotIn('_auth_user_id', client.session)
        self.assertEqual(client.session.get('mcp_approval_return_path'), url.removeprefix('http://testserver'))

    def test_owner_can_approve_an_agent_they_did_not_create(self):
        row = self._row()
        client = Client()
        client.force_login(self.owner)
        url, token, page = self._open(client, row)
        self.assertContains(page, 'Approve')
        client.post(url, {'decision': 'approve', 'token': token})
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_APPROVED)
        self.assertEqual(row.decided_by_id, self.owner.pk)

    def test_deny_once(self):
        row = self._row(is_destructive=False)
        client = Client()
        client.force_login(self.member)
        url, token, page = self._open(client, row)
        self.assertContains(page, 'This tool is not marked as destructive.')
        denied = client.post(url, {'decision': 'deny', 'token': token})
        self.assertContains(denied, 'Denied')
        self.assertContains(denied, 'Nothing was changed.')
        self.assertNotContains(denied, 'name="decision"')
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_REJECTED)

    def test_second_decision_does_not_change_the_first(self):
        row = self._row()
        client = Client()
        client.force_login(self.member)
        url, token, _page = self._open(client, row)
        client.post(url, {'decision': 'approve', 'token': token})
        events = EventLog.objects.filter(event_type='identity.mcp.approval_decision').count()
        again = client.post(url, {'decision': 'approve', 'token': token})
        self.assertContains(again, 'This request was already approved.')
        self.assertContains(again, 'will keep working')
        flipped = client.post(url, {'decision': 'deny', 'token': token})
        self.assertContains(flipped, 'This request was already approved.')
        self.assertNotContains(flipped, 'name="decision"')
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_APPROVED)
        self.assertEqual(EventLog.objects.filter(event_type='identity.mcp.approval_decision').count(), events)

    def test_signed_out_user_is_sent_to_company_sign_in(self):
        row = self._row()
        client = Client()
        response = client.get(self._url(row))
        self.assertRedirects(response, '/oauth/mcp/signin', fetch_redirect_response=False)
        signin = client.get('/oauth/mcp/signin')
        self.assertContains(signin, 'Sign in to decide this request')
        self.assertContains(signin, 'Writer wants to run write_file for Acme.')
        self.assertContains(signin, 'Email me a sign-in link')
        self.assertNotContains(signin, 'name="decision"')
        client.force_login(self.member)
        continued = client.post('/oauth/mcp/signin', {'account_choice': 'continue'})
        self.assertEqual(continued.status_code, 302)
        self.assertIn(f'/oauth/mcp/approval/{row.id}', continued['Location'])
        page = client.get(continued['Location'])
        self.assertContains(page, 'Approve this action?')
        self.assertContains(page, 'Create notes.txt in Marketing')

    def test_sign_in_lists_configured_oauth_provider(self):
        app = SocialApp.objects.create(
            provider='github',
            name='GitHub',
            client_id='cid-approval',
            secret='secret-approval',
            settings={'catalog_slug': 'github'},
        )
        CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        self.company.enable_magic_link = False
        self.company.save(update_fields=['enable_magic_link'])
        row = self._row()
        client = Client()
        client.get(self._url(row))
        signin = client.get('/oauth/mcp/signin')
        self.assertContains(signin, 'Continue with GitHub')
        self.assertNotContains(signin, 'Email me a sign-in link')
        self.assertContains(signin, 'code_challenge=')

    def test_sign_in_explains_when_the_company_has_no_method(self):
        self.company.enable_magic_link = False
        self.company.save(update_fields=['enable_magic_link'])
        row = self._row()
        client = Client()
        client.get(self._url(row))
        signin = client.get('/oauth/mcp/signin')
        self.assertContains(signin, 'Acme has no sign-in method that works here.')
        self.assertNotContains(signin, 'Email me a sign-in link')

    def test_wrong_user_cannot_decide(self):
        row = self._row()
        client = Client()
        client.force_login(self.other)
        response = client.get(self._url(row))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'This account cannot decide this request', status_code=403)
        self.assertContains(response, 'Signed in as other@acme.com', status_code=403)
        self.assertNotContains(response, 'Create notes.txt in Marketing', status_code=403)
        self.assertNotContains(response, 'name="decision"', status_code=403)
        self.assertContains(response, 'Use another account', status_code=403)
        posted = client.post(self._url(row), {'decision': 'approve', 'token': self._url(row).split('token=', 1)[1]})
        self.assertEqual(posted.status_code, 403)
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_PENDING)

    def test_staff_cannot_decide(self):
        row = self._row()
        client = Client()
        client.force_login(self.staff)
        response = client.get(self._url(row))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Staff accounts cannot authorize MCP agents.', status_code=403)
        self.assertContains(response, 'Signed in as staff@acme.com', status_code=403)
        self.assertNotContains(response, 'name="decision"', status_code=403)
        posted = client.post(self._url(row), {'decision': 'approve', 'token': self._url(row).split('token=', 1)[1]})
        self.assertEqual(posted.status_code, 403)
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_PENDING)
        self.assertContains(response, 'Use another account', status_code=403)

    def test_expired_request_has_no_buttons(self):
        row = self._row(expires_at=timezone.now() - timedelta(minutes=1))
        client = Client()
        client.force_login(self.member)
        response = client.get(self._url(row))
        self.assertContains(response, 'This approval is no longer valid')
        self.assertContains(response, 'This request expired before a decision.')
        self.assertNotContains(response, 'name="decision"')
        event = EventLog.objects.filter(event_type='identity.mcp.approval_decision').latest('id')
        self.assertEqual(event.data['status'], 'expired')

    def test_already_denied_has_no_buttons(self):
        row = self._row(status=McpApprovalRequest.STATUS_REJECTED)
        client = Client()
        client.force_login(self.member)
        url = self._url(row)
        response = client.get(url)
        self.assertContains(response, 'Denied')
        self.assertContains(response, 'This request was already denied.')
        self.assertNotContains(response, 'name="decision"')
        client.post(url, {'decision': 'approve', 'token': url.split('token=', 1)[1]})
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_REJECTED)

    def test_unknown_link(self):
        client = Client()
        missing = client.get(f'/oauth/mcp/approval/{uuid.uuid4()}')
        self.assertContains(missing, 'This approval was not found', status_code=404)
        self.assertNotContains(missing, 'Acme', status_code=404)
        row = self._row()
        bad = client.get(f'/oauth/mcp/approval/{row.id}?token=not-a-token')
        self.assertContains(bad, 'This approval was not found', status_code=404)
        self.assertNotContains(bad, 'Create notes.txt in Marketing', status_code=404)

    def test_global_row_cannot_be_decided_here(self):
        row = McpApprovalRequest.objects.create(
            agent=None,
            company=None,
            service='storage',
            action='write_file',
            arguments_hash='g' * 64,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        client = Client()
        client.force_login(self.owner)
        response = client.get(self._url(row))
        self.assertContains(response, 'This request cannot be decided here')
        self.assertNotContains(response, 'name="decision"')

    def test_french_copy(self):
        row = self._row()
        client = Client()
        client.force_login(self.member)
        url = self._url(row)
        token = url.split('token=', 1)[1]
        page = client.get(url, HTTP_ACCEPT_LANGUAGE='fr')
        self.assertContains(page, 'Approuver cette action ?')
        self.assertContains(page, 'Connecté en tant que member@acme.com')
        self.assertContains(page, 'Utiliser un autre compte')
        self.assertContains(page, 'Entreprise')
        self.assertContains(page, 'Outil')
        self.assertContains(page, 'Approuver')
        self.assertContains(page, 'Refuser')
        self.assertContains(page, 'marqué comme destructif')

    def test_post_requires_csrf(self):
        row = self._row()
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.member)
        url = self._url(row)
        token = url.split('token=', 1)[1]
        page = client.get(url)
        csrf = client.cookies['csrftoken'].value
        blocked = client.post(url, {'decision': 'approve', 'token': token})
        self.assertEqual(blocked.status_code, 403)
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_PENDING)
        csrf = client.cookies['csrftoken'].value
        approved = client.post(
            url,
            {'decision': 'approve', 'token': token, 'csrfmiddlewaretoken': csrf},
        )
        self.assertContains(approved, 'Approved')
        row.refresh_from_db()
        self.assertEqual(row.status, McpApprovalRequest.STATUS_APPROVED)
        self.assertEqual(page.status_code, 200)

    def _assertion(self, *, args_hash: str, action: str = 'write_file'):
        return build_mcp_approval_assertion_for_agent(
            self.agent,
            **TEST_CALLER_SIGNING,
            company_id=self.company.id,
            agent_id=str(self.agent.id),
            service='storage',
            action=action,
            arguments_hash=args_hash,
            audience_url='https://identity.test',
        )

    def _create(self, body: dict, *, args_hash: str, action: str = 'write_file'):
        return self.client.post(
            '/api/v1/mcp/internal/mcp-approval-requests',
            data=json.dumps(body),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(args_hash=args_hash, action=action)}',
        )

    def test_create_and_state_return_approval_url(self):
        created = self._create(
            {'is_destructive': True, 'arguments_summary': 'Delete notes.txt'},
            args_hash='a' * 64,
            action='delete_object',
        )
        self.assertEqual(created.status_code, 200, created.content)
        body = created.json()
        self.assertEqual(
            set(body),
            {'id', 'status', 'expires_at', 'is_destructive', 'fallback_path', 'approval_url'},
        )
        self.assertEqual(body['status'], 'pending')
        self.assertTrue(body['is_destructive'])
        self.assertTrue(body['fallback_path'].startswith(f'/oauth/mcp/approval/{body["id"]}?token='))
        self.assertTrue(
            body['approval_url'].startswith(f'https://identity.test/oauth/mcp/approval/{body["id"]}?token=')
        )
        self.assertEqual(urlsplit(body['approval_url']).scheme, 'https')
        row = McpApprovalRequest.objects.get(pk=body['id'])
        self.assertEqual(row.short_action_summary, 'Delete notes.txt')
        self.assertEqual(row.arguments_redacted, {})

        state = self.client.post(
            '/api/v1/mcp/internal/mcp-approval-state',
            data='{}',
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._assertion(args_hash="a" * 64, action="delete_object")}',
        )
        self.assertEqual(state.status_code, 200, state.content)
        polled = state.json()
        self.assertEqual(
            set(polled),
            {'id', 'status', 'expires_at', 'is_destructive', 'approval_url'},
        )
        self.assertEqual(polled['id'], body['id'])
        self.assertEqual(polled['status'], 'pending')
        self.assertEqual(polled['expires_at'], body['expires_at'])
        self.assertTrue(polled['is_destructive'])
        self.assertTrue(polled['approval_url'].startswith(f'https://identity.test/oauth/mcp/approval/{body["id"]}?token='))

        from apps.authapi.views import _issue_shellui_tokens

        access = _issue_shellui_tokens(self.member, company=self.company)['access_token']
        listed = self.client.get('/api/v1/mcp/approvals', HTTP_AUTHORIZATION=f'Bearer {access}')
        self.assertEqual(listed.status_code, 200)
        pending = listed.json()['approvals']
        self.assertEqual(len(pending), 1)
        self.assertTrue(
            pending[0]['approval_url'].startswith(f'https://identity.test/oauth/mcp/approval/{body["id"]}?token=')
        )
        self.assertEqual(pending[0]['short_action_summary'], 'Delete notes.txt')

    def test_arguments_summary_must_be_a_short_string(self):
        too_long = self._create({'arguments_summary': 'x' * 501}, args_hash='b' * 64)
        self.assertEqual(too_long.status_code, 400)
        nested = self._create({'arguments_summary': {'path': 'notes.txt'}}, args_hash='c' * 64)
        self.assertEqual(nested.status_code, 400)
        raw = self._create({'arguments': {'path': 'notes.txt'}}, args_hash='d' * 64)
        self.assertEqual(raw.status_code, 400)
        collapsed = self._create({'arguments_summary': '  hello\nworld  '}, args_hash='e' * 64, action='rename')
        self.assertEqual(collapsed.status_code, 200, collapsed.content)
        row = McpApprovalRequest.objects.get(pk=collapsed.json()['id'])
        self.assertEqual(row.short_action_summary, 'hello world')
