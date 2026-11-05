import json
from urllib.parse import quote, urlencode

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from apps.agents.tests.mcp_test_settings import TEST_CALLER_SIGNING, TRUSTED_TEST_CALLER_SETTINGS
from apps.agents.tests.mcp_test_settings import rs256_identity_settings
from apps.authapi.client_pkce import s256_challenge
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.agents.models import Agent, McpOAuthClient
from apps.agents.staff import is_mcp_oauth_refused_user
from apps.agents.tokens import encode_access_token

User = get_user_model()

IDENTITY_MCP_RESOURCE = 'https://identity.test/mcp'


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    MCP_DYNAMIC_CLIENT_REGISTRATION=True,
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpOAuthMetadataTests(TestCase):
    def test_authorization_server_metadata(self):
        response = self.client.get('/.well-known/oauth-authorization-server')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['issuer'], 'https://identity.test')
        self.assertIn('registration_endpoint', data)
        self.assertEqual(data['code_challenge_methods_supported'], ['S256'])
        self.assertTrue(data.get('resource_indicators_supported'))

    def test_protected_resource_metadata(self):
        response = self.client.get('/.well-known/oauth-protected-resource')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['resource'], 'https://identity.test/mcp')


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    MCP_DYNAMIC_CLIENT_REGISTRATION=True,
    AUTH_RATE_LIMIT_ENABLED=False,
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
    AI_SERVICE_URL='https://ai.test',
)
class McpOAuthFlowTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-mcp')
        self.owner = User.objects.create_user(username='owner', email='owner@acme.com', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.verifier = 'a' * 43
        self.challenge = s256_challenge(self.verifier)

    def test_dynamic_registration_and_token_refused_for_staff(self):
        reg = self.client.post(
            '/oauth/mcp/register',
            data=json.dumps({'redirect_uris': ['http://127.0.0.1/cb'], 'client_name': 'Cursor'}),
            content_type='application/json',
        )
        self.assertEqual(reg.status_code, 201)
        client_id = reg.json()['client_id']
        staff = User.objects.create_user(username='staff', password='unused', is_staff=True)
        self.assertTrue(is_mcp_oauth_refused_user(staff))
        client = Client()
        client.force_login(staff)
        query = urlencode(
            {
                'client_id': client_id,
                'redirect_uri': 'http://127.0.0.1/cb',
                'response_type': 'code',
                'code_challenge': self.challenge,
                'code_challenge_method': 'S256',
                'resource': f'https://ai.test/c/{self.company.id}/mcp',
            }
        )
        response = client.get(f'/oauth/mcp/authorize?{query}')
        self.assertEqual(response.status_code, 403)

    def test_agent_access_token_and_revocation_list(self):
        reg = self.client.post(
            '/oauth/mcp/register',
            data=json.dumps({'redirect_uris': ['http://127.0.0.1/cb']}),
            content_type='application/json',
        )
        client_id = reg.json()['client_id']
        oauth_client = McpOAuthClient.objects.get(client_id=client_id)
        agent = Agent.objects.create(
            company=self.company,
            name='Test agent',
            oauth_client=oauth_client,
            created_by=self.owner,
            services_allowed=['identity'],
        )
        access = encode_access_token(agent, resource=IDENTITY_MCP_RESOURCE)
        import jwt

        payload = jwt.decode(access, options={'verify_signature': False})
        self.assertEqual(payload['agent_id'], str(agent.id))
        self.assertEqual(payload['aud'], IDENTITY_MCP_RESOURCE)
        self.assertEqual(payload['company_name'], self.company.name)
        from shellui_django.mcp.internal import build_mcp_revocation_assertion

        assertion = build_mcp_revocation_assertion(audience_url='https://identity.test', **TEST_CALLER_SIGNING)
        with rs256_identity_settings() as (_signing, jwks):
            from shellui_django.mcp.internal import parse_trusted_revocation_poll_response

            revoked = self.client.get(
                '/api/v1/mcp/internal/mcp-revocations',
                HTTP_AUTHORIZATION=f'Bearer {assertion}',
            )
            self.assertEqual(revoked.status_code, 200)
            data = revoked.json()
            self.assertEqual(data['cache_seconds'], 30)
            self.assertIn('revocation_assertion', data)
            self.assertIn('agents', data)
            self.assertEqual(data['revoked_agent_ids'], [])
            ids, cache, _agents = parse_trusted_revocation_poll_response(
                data,
                expected_issuer='https://identity.test',
                jwks=jwks,
            )
            self.assertEqual(ids, frozenset())
            self.assertEqual(cache, 30)
            agent.revoked_at = agent.created_at
            agent.save(update_fields=['revoked_at'])
            # Each assertion is single use, so the second poll signs a fresh one.
            assertion = build_mcp_revocation_assertion(audience_url='https://identity.test', **TEST_CALLER_SIGNING)
            revoked2 = self.client.get(
                '/api/v1/mcp/internal/mcp-revocations',
                HTTP_AUTHORIZATION=f'Bearer {assertion}',
            )
            data2 = revoked2.json()
            self.assertIn(str(agent.id), data2['revoked_agent_ids'])
            ids2, _, _ = parse_trusted_revocation_poll_response(
                data2,
                expected_issuer='https://identity.test',
                jwks=jwks,
            )
            self.assertIn(str(agent.id), ids2)

    def test_revocation_list_unavailable_without_rs256_signing(self):
        from shellui_django.mcp.internal import build_mcp_revocation_assertion

        assertion = build_mcp_revocation_assertion(audience_url='https://identity.test', **TEST_CALLER_SIGNING)
        response = self.client.get(
            '/api/v1/mcp/internal/mcp-revocations',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        self.assertEqual(response.status_code, 503)
        self.assertIn('error', response.json())

    def test_revocation_list_requires_assertion(self):
        response = self.client.get('/api/v1/mcp/internal/mcp-revocations')
        self.assertEqual(response.status_code, 401)
