import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.agents.models import Agent, AgentRefreshSession, McpApprovalRequest, McpOAuthClient
from apps.agents.oauth_codes import hash_authorization_code, issue_mcp_authorization_code
from apps.agents.tokens import encode_access_token, issue_agent_refresh, refresh_agent_access

User = get_user_model()

IDENTITY_MCP_RESOURCE = 'https://identity.test/mcp'


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    MCP_DYNAMIC_CLIENT_REGISTRATION=True,
    AUTH_RATE_LIMIT_ENABLED=False,
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
)
class McpOAuthRedirectValidationTests(TestCase):
    def test_registration_rejects_open_redirect_path(self):
        response = self.client.post(
            '/oauth/mcp/register',
            data=json.dumps({'redirect_uris': ['/oauth/callback']}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 400)

    def test_registration_rejects_javascript_scheme(self):
        response = self.client.post(
            '/oauth/mcp/register',
            data=json.dumps({'redirect_uris': ['javascript:alert(1)']}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 400)


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpRefreshReuseTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Reuse Co', slug='reuse-co')
        self.owner = User.objects.create_user(username='reuse-owner', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.agent = Agent.objects.create(company=self.company, name='A', created_by=self.owner)

    def test_reused_refresh_revokes_all_agent_sessions(self):
        first_refresh, session = issue_agent_refresh(self.agent, resource=IDENTITY_MCP_RESOURCE)
        rotated = refresh_agent_access(first_refresh, resource=IDENTITY_MCP_RESOURCE)
        self.assertIsNotNone(rotated)
        reuse = refresh_agent_access(first_refresh, resource=IDENTITY_MCP_RESOURCE)
        self.assertIsNone(reuse)
        active = AgentRefreshSession.objects.filter(agent=self.agent, revoked_at__isnull=True).count()
        self.assertEqual(active, 0)


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpAuthorizationCodeStorageTests(TestCase):
    def test_code_digest_is_stored_not_plaintext(self):
        plain, digest = issue_mcp_authorization_code()
        self.assertNotEqual(plain, digest)
        self.assertEqual(digest, hash_authorization_code(plain))


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpAgentApprovalGuardTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Approve Co', slug='approve-co')
        self.owner = User.objects.create_user(username='approve-owner', password='unused')
        self.other_owner = User.objects.create_user(username='other-owner', password='unused')
        self.company.owners.add(self.owner, self.other_owner)
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.other_owner, enabled=True)
        client_row = McpOAuthClient.objects.create(client_id='cid', redirect_uris=['http://127.0.0.1/cb'])
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            oauth_client=client_row,
            created_by=self.owner,
            services_allowed=['identity'],
        )

    def test_agent_bearer_cannot_approve_pending_request(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='identity',
            action='write',
            arguments_hash='abc',
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        access = encode_access_token(self.agent, resource=IDENTITY_MCP_RESOURCE)
        response = self.client.post(
            f'/api/v1/mcp/approvals/{row.id}/approve',
            HTTP_AUTHORIZATION=f'Bearer {access}',
        )
        self.assertEqual(response.status_code, 403)

    def test_company_owner_can_approve_with_user_token(self):
        row = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='identity',
            action='write',
            arguments_hash='def',
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        from apps.authapi.views import _issue_shellui_tokens

        token = _issue_shellui_tokens(self.other_owner, company=self.company)['access_token']
        response = self.client.post(
            f'/api/v1/mcp/approvals/{row.id}/approve',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 200)
