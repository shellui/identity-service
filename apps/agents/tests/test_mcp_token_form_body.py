"""MCP OAuth token and registration accept RFC 6749 form-urlencoded bodies."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlencode, urlsplit

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from apps.authapi.client_pkce import s256_challenge
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.agents.models import McpOAuthClient

User = get_user_model()

SETTINGS = dict(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AI_SERVICE_URL='https://ai.test',
    MCP_DYNAMIC_CLIENT_REGISTRATION=True,
    AUTH_RATE_LIMIT_ENABLED=False,
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
)
REDIRECT = 'http://127.0.0.1:6274/oauth/callback'


@override_settings(**SETTINGS)
class McpOAuthFormBodyTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-form-token')
        self.user = User.objects.create_user(username='ella', email='ella@acme.com', password='unused')
        set_company_access(self.company, self.user, enabled=True)
        self.client_row = McpOAuthClient.objects.create(
            client_id='form-client',
            client_name='Inspector',
            redirect_uris=[REDIRECT],
        )
        self.verifier = 'v' * 43
        self.challenge = s256_challenge(self.verifier)
        self.resource = f'https://ai.test/c/{self.company.id}/mcp'

    def _authorize_query(self):
        return urlencode(
            {
                'response_type': 'code',
                'client_id': self.client_row.client_id,
                'redirect_uri': REDIRECT,
                'code_challenge': self.challenge,
                'code_challenge_method': 'S256',
                'resource': self.resource,
                'state': 'st',
            }
        )

    def _issue_code_via_consent(self) -> str:
        client = Client()
        client.force_login(self.user)
        approved = client.post(
            '/oauth/mcp/authorize?' + self._authorize_query(),
            {
                'response_type': 'code',
                'client_id': self.client_row.client_id,
                'redirect_uri': REDIRECT,
                'code_challenge': self.challenge,
                'code_challenge_method': 'S256',
                'resource': self.resource,
                'state': 'st',
                'decision': 'approve',
                'services': ['identity', 'ai'],
                'access_mode': 'ask',
                'read_level': 'safe',
            },
        )
        self.assertEqual(approved.status_code, 302)
        params = parse_qs(urlsplit(approved['Location']).query)
        return params['code'][0]

    def test_form_body_without_json_content_type_is_not_invalid_json(self):
        """Reproduces MCP Inspector: curl -d grant_type=authorization_code (form, not JSON)."""
        response = self.client.post('/oauth/mcp/token', data={'grant_type': 'authorization_code'})
        self.assertNotEqual(response.json().get('error'), 'invalid_json')
        with_client = self.client.post(
            '/oauth/mcp/token',
            data={
                'grant_type': 'authorization_code',
                'client_id': self.client_row.client_id,
                'redirect_uri': REDIRECT,
            },
        )
        self.assertEqual(with_client.status_code, 400)
        self.assertEqual(with_client.json()['error'], 'invalid_grant')

    def test_malformed_json_body_returns_invalid_request(self):
        response = self.client.post(
            '/oauth/mcp/token',
            data='not-json',
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_request')

    def test_authorization_code_grant_form_urlencoded_with_pkce(self):
        code = self._issue_code_via_consent()
        response = self.client.post(
            '/oauth/mcp/token',
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT,
                'client_id': self.client_row.client_id,
                'code_verifier': self.verifier,
                'resource': self.resource,
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)
        self.assertEqual(data['token_type'], 'Bearer')

    def test_authorization_code_grant_json_still_works(self):
        code = self._issue_code_via_consent()
        response = self.client.post(
            '/oauth/mcp/token',
            data=json.dumps(
                {
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT,
                    'client_id': self.client_row.client_id,
                    'code_verifier': self.verifier,
                    'resource': self.resource,
                }
            ),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', response.json())

    def test_refresh_token_grant_form_urlencoded(self):
        code = self._issue_code_via_consent()
        first = self.client.post(
            '/oauth/mcp/token',
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT,
                'client_id': self.client_row.client_id,
                'code_verifier': self.verifier,
                'resource': self.resource,
            },
        )
        refresh = first.json()['refresh_token']
        rotated = self.client.post(
            '/oauth/mcp/token',
            data={
                'grant_type': 'refresh_token',
                'refresh_token': refresh,
                'resource': self.resource,
            },
        )
        self.assertEqual(rotated.status_code, 200)
        self.assertIn('access_token', rotated.json())
        self.assertIn('refresh_token', rotated.json())

    def test_unsupported_grant_type_form_encoded(self):
        response = self.client.post('/oauth/mcp/token', data={'grant_type': 'client_credentials'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'unsupported_grant_type')

    def test_dynamic_registration_form_urlencoded(self):
        response = self.client.post(
            '/oauth/mcp/register',
            data={
                'redirect_uris': REDIRECT,
                'client_name': 'Claude',
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertIn('client_id', response.json())

    def test_dynamic_registration_json_still_works(self):
        response = self.client.post(
            '/oauth/mcp/register',
            data=json.dumps({'redirect_uris': [REDIRECT], 'client_name': 'ChatGPT'}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 201)
