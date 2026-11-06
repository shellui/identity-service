"""POST /api/v1/mcp/internal/mcp-agent-delegated-authority (live delegated agent binding)."""

from __future__ import annotations

import json
import time
import uuid

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.agents.mcp_delegated_authority import (
    DELEGATED_AGENT_AUTHORITY_AUDIENCE,
    DELEGATED_AGENT_AUTHORITY_SCOPE,
)
from apps.agents.models import Agent, GlobalAgentRevocation, McpOAuthClient
from apps.agents.tests.mcp_test_settings import (
    TRUSTED_AI_TEST_CALLER_SETTINGS,
    TRUSTED_TEST_CALLER_SETTINGS,
    TEST_AI_CALLER_SIGNING,
    TEST_CALLER_SIGNING,
)
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()


def _delegated_authority_assertion(
    *,
    audience_url: str,
    issuer: str | None = None,
    sub: str = 'service',
    signing: dict | None = None,
) -> str:
    signing = signing or TEST_CALLER_SIGNING
    iss = (issuer or signing['issuer']).strip().rstrip('/')
    now = int(time.time())
    claims = {
        'iss': iss,
        'aud': DELEGATED_AGENT_AUTHORITY_AUDIENCE,
        'sub': sub,
        'scope': DELEGATED_AGENT_AUTHORITY_SCOPE,
        'target': audience_url.rstrip('/'),
        'iat': now,
        'exp': now + 60,
        'jti': uuid.uuid4().hex,
    }
    token = jwt.encode(
        claims,
        signing['private_key_pem'],
        algorithm='RS256',
        headers={'kid': signing['kid']},
    )
    return token.decode('utf-8') if isinstance(token, bytes) else token


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    **TRUSTED_AI_TEST_CALLER_SETTINGS,
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpDelegatedAgentAuthorityTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Co', slug='co-del-auth')
        self.owner = User.objects.create_user('o', 'o@test.com', 'x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        cl = McpOAuthClient.objects.create(client_id='cid-da', redirect_uris=['http://127.0.0.1/cb'])
        self.gid = uuid.uuid4()
        self.saas_gc = uuid.uuid4()
        self.agent = Agent.objects.create(
            company=self.company,
            name='Del',
            oauth_client=cl,
            created_by=self.owner,
            services_allowed=['storage', 'ai'],
            global_agent_id=self.gid,
            global_company_id=self.saas_gc,
            company_binding_version=0,
            grant_version=0,
            global_allowed_services=['storage', 'ai'],
        )

    def _post(self, body: dict, *, path: str | None = None, issuer: str | None = None, sub: str = 'service'):
        assertion = _delegated_authority_assertion(
            audience_url='https://identity.test',
            issuer=issuer,
            sub=sub,
        )
        url = path or '/api/v1/mcp/internal/mcp-agent-delegated-authority'
        return self.client.post(
            url,
            data=json.dumps(body),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )

    def _ok_body(self):
        return {
            'agent_id': str(self.agent.id),
            'company_id': self.company.pk,
            'global_company_id': str(self.saas_gc),
            'grant_version': 0,
            'company_binding_version': 0,
        }

    def test_storage_caller_ok(self):
        r = self._post(self._ok_body())
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['authorized'])
        self.assertTrue(data['active'])
        self.assertFalse(data['revoked'])
        self.assertFalse(data['paused'])
        self.assertEqual(data['global_agent_id'], str(self.gid))
        self.assertEqual(data['global_company_id'], str(self.saas_gc))
        self.assertEqual(data['grant_version'], 0)
        self.assertEqual(data['company_binding_version'], 0)

    def test_alias_paths_same_handler(self):
        body = self._ok_body()
        p1 = '/api/v1/mcp/internal/mcp-delegated-authority'
        p2 = '/api/v1/mcp/internal/mcp-delegated-agent-authority'
        a = self._post(body, path=p1)
        b = self._post(body, path=p2)
        self.assertEqual(a.status_code, 200, a.content)
        self.assertEqual(b.status_code, 200, b.content)
        self.assertEqual(a.json()['global_agent_id'], b.json()['global_agent_id'])

    def test_missing_assertion_404(self):
        r = self.client.post(
            '/api/v1/mcp/internal/mcp-agent-delegated-authority',
            data=json.dumps(self._ok_body()),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 404)

    def test_unknown_body_key_400(self):
        body = {**self._ok_body(), 'global_agent_id': str(self.gid)}
        r = self._post(body)
        self.assertEqual(r.status_code, 400)

    def test_grant_version_mismatch_200_inactive(self):
        body = self._ok_body()
        body['grant_version'] = 1
        r = self._post(body)
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertFalse(d['authorized'])
        self.assertFalse(d['active'])
        self.assertEqual(d['agent_id'], str(self.agent.id))
        self.assertEqual(d['company_id'], self.company.pk)
        self.assertEqual(d['global_company_id'], str(self.saas_gc))
        self.assertEqual(d['grant_version'], 1)
        self.assertEqual(d['company_binding_version'], 0)

    def test_global_company_mismatch_200_inactive(self):
        body = self._ok_body()
        body['global_company_id'] = str(uuid.uuid4())
        r = self._post(body)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()['authorized'])

    def test_personal_agent_404(self):
        self.agent.global_agent_id = None
        self.agent.save(update_fields=['global_agent_id'])
        r = self._post(self._ok_body())
        self.assertEqual(r.status_code, 404)

    def test_paused_200_unauthorized(self):
        self.agent.paused_at = timezone.now()
        self.agent.save(update_fields=['paused_at'])
        r = self._post(self._ok_body())
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertFalse(d['authorized'])
        self.assertFalse(d['active'])
        self.assertFalse(d['revoked'])
        self.assertTrue(d['paused'])

    def test_global_registry_revoked_200(self):
        GlobalAgentRevocation.objects.create(global_agent_id=self.gid)
        r = self._post(self._ok_body())
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertFalse(d['authorized'])
        self.assertFalse(d['active'])
        self.assertTrue(d['revoked'])
        self.assertIn('revoked_at', d)

    def test_extra_assertion_claim_401(self):
        signing = TEST_CALLER_SIGNING
        now = int(time.time())
        claims = {
            'iss': signing['issuer'],
            'aud': DELEGATED_AGENT_AUTHORITY_AUDIENCE,
            'sub': 'service',
            'scope': DELEGATED_AGENT_AUTHORITY_SCOPE,
            'target': 'https://identity.test',
            'iat': now,
            'exp': now + 60,
            'jti': uuid.uuid4().hex,
            'extra': 'nope',
        }
        token = jwt.encode(
            claims,
            signing['private_key_pem'],
            algorithm='RS256',
            headers={'kid': signing['kid']},
        )
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        r = self.client.post(
            '/api/v1/mcp/internal/mcp-agent-delegated-authority',
            data=json.dumps(self._ok_body()),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(r.status_code, 401)

    def test_invalid_types_400(self):
        for body in (
            {**self._ok_body(), 'grant_version': '0'},
            {**self._ok_body(), 'company_binding_version': True},
            {**self._ok_body(), 'company_binding_version': 1.0},
            {**self._ok_body(), 'company_id': '42'},
        ):
            r = self._post(body)
            self.assertEqual(r.status_code, 400, body)

    def test_ai_issuer_ok(self):
        assertion = _delegated_authority_assertion(
            audience_url='https://identity.test',
            issuer=TEST_AI_CALLER_SIGNING['issuer'],
            signing=TEST_AI_CALLER_SIGNING,
        )
        r = self.client.post(
            '/api/v1/mcp/internal/mcp-agent-delegated-authority',
            data=json.dumps(self._ok_body()),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['authorized'])

    def test_dashboard_caller_forbidden(self):
        from apps.authapi.jwks import generate_rsa_key_pair, load_signing_key

        priv, pub = generate_rsa_key_pair(2048)
        signing = load_signing_key(private_pem=priv, public_pem=pub)
        dash_iss = 'https://dashboard.prov.test'
        pub_pem = signing.public_pem
        if isinstance(pub_pem, bytes):
            pub_pem = pub_pem.decode('utf-8')
        with self.settings(
            PROVISIONING_ISSUER=dash_iss,
            PROVISIONING_PUBLIC_KEY=pub_pem,
        ):
            now = int(time.time())
            token = jwt.encode(
                {
                    'iss': dash_iss,
                    'aud': DELEGATED_AGENT_AUTHORITY_AUDIENCE,
                    'sub': 'service',
                    'scope': DELEGATED_AGENT_AUTHORITY_SCOPE,
                    'target': 'https://identity.test',
                    'iat': now,
                    'exp': now + 60,
                    'jti': uuid.uuid4().hex,
                },
                priv,
                algorithm='RS256',
                headers={'kid': signing.kid},
            )
            token = token.decode('utf-8') if isinstance(token, bytes) else token
            r = self.client.post(
                '/api/v1/mcp/internal/mcp-agent-delegated-authority',
                data=json.dumps(self._ok_body()),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
            )
            self.assertEqual(r.status_code, 403)
