"""Downstream MCP access token delegation (AI service connector)."""

from __future__ import annotations

import json
import logging
import time
import uuid
from unittest.mock import patch

import jwt
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.agents.models import Agent
from apps.agents.tests.mcp_test_settings import rs256_identity_settings
from apps.authapi.jwks import build_jwks_document, generate_rsa_key_pair, load_signing_key
from apps.companies.access import set_company_access
from apps.companies.models import Company
from shellui_django.mcp.delegation import (
    DOWNSTREAM_TOKEN_AUDIENCE,
    DOWNSTREAM_TOKEN_SCOPE,
    sign_downstream_token_request,
)

User = get_user_model()

PATH = '/api/v1/mcp/internal/mcp-downstream-access-token'
IDENTITY_MCP = 'https://identity.test/mcp'
STORAGE_MCP = 'https://storage.test/mcp'
AI_ISSUER = 'https://ai.test'
AI_ORIGIN = 'https://ai.test'


def _ai_keys():
    private, public = generate_rsa_key_pair(2048)
    signing = load_signing_key(private_pem=private, public_pem=public, kid='ai-test')
    jwks = build_jwks_document(signing)
    return private, jwks, signing.kid


def _delegation_request(
    private_pem: str,
    kid: str,
    *,
    agent_id: str,
    company_id: int,
    resource: str,
    issuer: str = AI_ISSUER,
    ttl: int = 60,
) -> str:
    return sign_downstream_token_request(
        private_pem,
        kid,
        issuer,
        agent_id,
        company_id,
        resource,
        ttl,
    )


def _post_mint(client, *, token: str, agent_id: str, company_id: int, resource: str):
    return client.post(
        PATH,
        data=json.dumps({'agent_id': agent_id, 'company_id': company_id, 'resource': resource}),
        content_type='application/json',
        HTTP_AUTHORIZATION=f'Bearer {token}',
    )


class _LogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())

    def attach(self) -> None:
        logging.getLogger().addHandler(self)

    def detach(self) -> None:
        logging.getLogger().removeHandler(self)

    def text(self) -> str:
        return '\n'.join(self.records)


class McpDownstreamAccessTokenTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ai_private, cls.ai_jwks, cls.ai_kid = _ai_keys()

    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Down Co', slug='down-co')
        self.other = Company.objects.create(name='Other Co', slug='other-co')
        self.owner = User.objects.create_user(username='down-owner', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            created_by=self.owner,
            services_allowed=['identity', 'storage'],
        )
        self.other_agent = Agent.objects.create(
            company=self.other,
            name='Other',
            created_by=self.owner,
            services_allowed=['identity', 'storage'],
        )
        self.settings_cm = override_settings(
            JWT_ISSUER='https://identity.test',
            JWT_AUDIENCE='shellui-test',
            STORAGE_SERVICE_URL='https://storage.test',
            AI_SERVICE_URL=AI_ORIGIN,
            AI_SERVICE_ISSUER=AI_ISSUER,
            AI_SERVICE_JWKS=self.ai_jwks,
            AUTH_RATE_LIMIT_ENABLED=True,
            MCP_RATE_LIMITS={
                'mcp_agent': {'limit': 1000, 'window': 60},
                'mcp_downstream_mint': {'limit': 1000, 'window': 60},
            },
            CACHES={
                'default': {
                    'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
                    'LOCATION': 'mcp-downstream-tests',
                }
            },
        )
        self.settings_cm.enable()
        self._rs256 = rs256_identity_settings()
        self._rs256.__enter__()

    def tearDown(self):
        self._rs256.__exit__(None, None, None)
        self.settings_cm.disable()

    def _sign(self, **kwargs):
        agent_id = kwargs.pop('agent_id', str(self.agent.id))
        company_id = kwargs.pop('company_id', self.company.id)
        resource = kwargs.pop('resource', STORAGE_MCP)
        return _delegation_request(
            self.ai_private,
            self.ai_kid,
            agent_id=agent_id,
            company_id=company_id,
            resource=resource,
            **kwargs,
        )

    def test_mints_access_token_for_allowed_resource(self):
        token = self._sign()
        response = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(response.status_code, 200)
        access = response.json()['access_token']
        payload = jwt.decode(access, options={'verify_signature': False})
        self.assertEqual(payload['aud'], STORAGE_MCP)
        self.assertEqual(payload['agent_id'], str(self.agent.id))
        self.assertEqual(payload['company_id'], self.company.id)

    def test_disabled_when_ai_service_not_configured(self):
        with override_settings(AI_SERVICE_URL='', AI_SERVICE_ISSUER='', AI_SERVICE_JWKS={}):
            response = self.client.post(PATH, data='{}', content_type='application/json')
        self.assertEqual(response.status_code, 404)

    def test_rejects_forged_signature(self):
        other_private, _, other_kid = _ai_keys()
        token = _delegation_request(
            other_private,
            other_kid,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        response = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(response.status_code, 401)

    def test_rejects_hs256(self):
        now = int(time.time())
        claims = {
            'iss': AI_ISSUER,
            'aud': DOWNSTREAM_TOKEN_AUDIENCE,
            'scope': DOWNSTREAM_TOKEN_SCOPE,
            'agent_id': str(self.agent.id),
            'company_id': self.company.id,
            'resource': STORAGE_MCP,
            'jti': uuid.uuid4().hex,
            'iat': now,
            'exp': now + 60,
        }
        token = jwt.encode(claims, 'secret', algorithm='HS256')
        response = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(response.status_code, 401)

    def test_rejects_expired_request(self):
        token = self._sign(ttl=1)
        time.sleep(7)
        response = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(response.status_code, 401)

    def test_rejects_reused_jti(self):
        token = self._sign()
        first = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(first.status_code, 200)
        second = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(second.status_code, 401)

    def test_rejects_wrong_issuer(self):
        token = self._sign(issuer='https://evil.test')
        response = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(response.status_code, 401)

    def test_rejects_agent_from_other_company(self):
        token = self._sign(agent_id=str(self.other_agent.id), company_id=self.other.id)
        response = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.other_agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(response.status_code, 400)

    def test_rejects_revoked_agent(self):
        self.agent.revoked_at = timezone.now()
        self.agent.save(update_fields=['revoked_at'])
        token = self._sign()
        response = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(response.status_code, 403)

    def test_rejects_unconfigured_resource(self):
        token = self._sign(resource='https://unknown.test/mcp')
        response = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource='https://unknown.test/mcp',
        )
        self.assertEqual(response.status_code, 403)

    def test_rejects_resource_not_allowed_for_agent(self):
        self.agent.services_allowed = ['identity']
        self.agent.save(update_fields=['services_allowed'])
        token = self._sign()
        response = _post_mint(
            self.client,
            token=token,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(response.status_code, 403)

    @patch('apps.agents.downstream_internal.encode_access_token', return_value='downstream-mint-leak-token')
    def test_no_token_in_logs(self, _encode):
        token = self._sign()
        capture = _LogCapture()
        capture.attach()
        try:
            response = _post_mint(
                self.client,
                token=token,
                agent_id=str(self.agent.id),
                company_id=self.company.id,
                resource=STORAGE_MCP,
            )
        finally:
            capture.detach()
        self.assertEqual(response.status_code, 200)
        joined = capture.text()
        self.assertNotIn('downstream-mint-leak-token', joined)
        self.assertNotIn('Bearer ', joined)


@override_settings(
    JWT_ISSUER='https://identity.test',
    STORAGE_SERVICE_URL='https://storage.test',
    AI_SERVICE_URL=AI_ORIGIN,
    AI_SERVICE_ISSUER=AI_ISSUER,
    AUTH_RATE_LIMIT_ENABLED=True,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'mcp-downstream-rate-agent',
        }
    },
)
class McpDownstreamAgentRateLimitTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ai_private, cls.ai_jwks, cls.ai_kid = _ai_keys()

    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Rate Co', slug='rate-co')
        self.owner = User.objects.create_user(username='rate-owner', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            created_by=self.owner,
            services_allowed=['identity', 'storage'],
        )
        self._settings = override_settings(
            AI_SERVICE_JWKS=self.ai_jwks,
            MCP_RATE_LIMITS={
                'mcp_agent': {'limit': 1, 'window': 60},
                'mcp_downstream_mint': {'limit': 1000, 'window': 60},
            },
        )
        self._settings.enable()
        self._rs256 = rs256_identity_settings()
        self._rs256.__enter__()

    def tearDown(self):
        self._rs256.__exit__(None, None, None)
        self._settings.disable()

    def test_rate_limit_per_agent(self):
        token_one = _delegation_request(
            self.ai_private,
            self.ai_kid,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        token_two = _delegation_request(
            self.ai_private,
            self.ai_kid,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        first = _post_mint(
            self.client,
            token=token_one,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        second = _post_mint(
            self.client,
            token=token_two,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)


@override_settings(
    JWT_ISSUER='https://identity.test',
    STORAGE_SERVICE_URL='https://storage.test',
    AI_SERVICE_URL=AI_ORIGIN,
    AI_SERVICE_ISSUER=AI_ISSUER,
    AUTH_RATE_LIMIT_ENABLED=True,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'mcp-downstream-rate-global',
        }
    },
)
class McpDownstreamGlobalRateLimitTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ai_private, cls.ai_jwks, cls.ai_kid = _ai_keys()

    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Global Rate Co', slug='global-rate-co')
        self.owner = User.objects.create_user(username='global-rate-owner', password='unused')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.agent = Agent.objects.create(
            company=self.company,
            name='Agent',
            created_by=self.owner,
            services_allowed=['identity', 'storage'],
        )
        self._settings = override_settings(
            AI_SERVICE_JWKS=self.ai_jwks,
            MCP_RATE_LIMITS={
                'mcp_agent': {'limit': 1000, 'window': 60},
                'mcp_downstream_mint': {'limit': 1, 'window': 60},
            },
        )
        self._settings.enable()
        self._rs256 = rs256_identity_settings()
        self._rs256.__enter__()

    def tearDown(self):
        self._rs256.__exit__(None, None, None)
        self._settings.disable()

    def test_rate_limit_global(self):
        token_one = _delegation_request(
            self.ai_private,
            self.ai_kid,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        token_two = _delegation_request(
            self.ai_private,
            self.ai_kid,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        first = _post_mint(
            self.client,
            token=token_one,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        second = _post_mint(
            self.client,
            token=token_two,
            agent_id=str(self.agent.id),
            company_id=self.company.id,
            resource=STORAGE_MCP,
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)
