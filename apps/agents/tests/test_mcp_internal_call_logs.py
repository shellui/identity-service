"""POST /api/v1/mcp/internal/mcp-call-logs trusted metadata (ai gateway #24)."""

from __future__ import annotations

import json
import time
import uuid
from datetime import timedelta

import jwt

from django.test import TestCase, override_settings
from django.utils import timezone
from shellui_django.mcp.internal import CALL_LOG_AUDIENCE, CALL_LOG_SCOPE

from apps.agents.models import Agent, McpApprovalRequest, McpCallLog
from apps.agents.tests.mcp_test_settings import (
    TEST_CALLER_SIGNING,
    TRUSTED_TEST_CALLER_SETTINGS,
    rs256_identity_settings,
)
from apps.authapi.jwks import build_jwks_document, generate_rsa_key_pair, load_signing_key
from apps.companies.models import Company

IDENTITY = 'https://identity.test'
CALL_LOGS = '/api/v1/mcp/internal/mcp-call-logs'

_AI_ISSUER = 'https://ai.test'
_AI_PRIV, _AI_PUB = generate_rsa_key_pair(2048)
_AI_KEY = load_signing_key(private_pem=_AI_PRIV, public_pem=_AI_PUB)
_AI_JWKS = build_jwks_document(_AI_KEY)


def _encode_call_log_assertion(*, issuer: str, private_pem: bytes, kid: str) -> str:
    now = int(time.time())
    claims = {
        'iss': issuer,
        'aud': CALL_LOG_AUDIENCE,
        'sub': 'service',
        'scope': CALL_LOG_SCOPE,
        'target': IDENTITY,
        'iat': now,
        'exp': now + 60,
        'jti': uuid.uuid4().hex,
    }
    token = jwt.encode(claims, private_pem, algorithm='RS256', headers={'kid': kid})
    return token.decode('utf-8') if isinstance(token, bytes) else token


@override_settings(
    JWT_ISSUER=IDENTITY,
    AUTH_RATE_LIMIT_ENABLED=False,
    **TRUSTED_TEST_CALLER_SETTINGS,
    AI_SERVICE_URL='https://ai.example',
    AI_SERVICE_ISSUER=_AI_ISSUER,
    AI_SERVICE_JWKS=_AI_JWKS,
)
class McpInternalCallLogTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-calllog')
        self.agent = Agent.objects.create(company=self.company, name='Agent', services_allowed=['identity'])

    def _ai_assertion(self) -> str:
        return _encode_call_log_assertion(
            issuer=_AI_ISSUER,
            private_pem=_AI_KEY.private_pem,
            kid=_AI_KEY.kid,
        )

    def _storage_assertion(self) -> str:
        return _encode_call_log_assertion(
            issuer=TEST_CALLER_SIGNING['issuer'],
            private_pem=TEST_CALLER_SIGNING['private_key_pem'],
            kid=TEST_CALLER_SIGNING['kid'],
        )

    def test_storage_legacy_body_without_audit_fields(self):
        body = {
            'agent_id': str(self.agent.id),
            'company_id': self.company.id,
            'service': 'storage',
            'tool': 'x',
            'status': 200,
            'duration_ms': 1,
            'result': 'ok',
        }
        with rs256_identity_settings():
            r = self.client.post(
                CALL_LOGS,
                data=json.dumps(body),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {self._storage_assertion()}',
            )
        self.assertEqual(r.status_code, 201, r.content)
        row = McpCallLog.objects.get(pk=r.json()['id'])
        self.assertEqual(row.operation_title, '')

    def test_ai_requires_allowlisted_keys(self):
        body = {
            'agent_id': str(self.agent.id),
            'company_id': self.company.id,
            'service': 'storage',
            'tool': 't',
            'status': 200,
            'duration_ms': 1,
            'operation_title': 'List buckets',
            'access_kind': 'read',
            'operation_result': 'success',
            'resource_label': 's3://acme/config',
            'evil': 'x',
        }
        with rs256_identity_settings():
            r = self.client.post(
                CALL_LOGS,
                data=json.dumps(body),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {self._ai_assertion()}',
            )
        self.assertEqual(r.status_code, 400)

    def test_ai_stores_trusted_metadata_and_links_approval(self):
        appr = McpApprovalRequest.objects.create(
            agent=self.agent,
            company=self.company,
            service='storage',
            action='put',
            arguments_hash='cd' * 32,
            expires_at=timezone.now() + timedelta(minutes=9),
        )
        body = {
            'agent_id': str(self.agent.id),
            'company_id': self.company.id,
            'service': 'storage',
            'tool': 'tools/call',
            'method': 'POST',
            'path': '/mcp',
            'status': 200,
            'duration_ms': 42,
            'arguments': {},
            'operation_title': 'Read file metadata',
            'access_kind': 'read',
            'operation_result': 'success',
            'resource_label': 'projects/acme/docs/readme',
            'approval_request_id': str(appr.id),
        }
        with rs256_identity_settings():
            r = self.client.post(
                CALL_LOGS,
                data=json.dumps(body),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {self._ai_assertion()}',
            )
        self.assertEqual(r.status_code, 201, r.content)
        row = McpCallLog.objects.get(pk=r.json()['id'])
        self.assertEqual(row.operation_title, 'Read file metadata')
        self.assertEqual(row.access_kind, 'read')
        self.assertEqual(row.operation_result, 'success')
        self.assertEqual(row.resource_label, 'projects/acme/docs/readme')
        self.assertEqual(row.company_name_snapshot, self.company.name)
        self.assertEqual(row.approval_request_id, appr.id)
