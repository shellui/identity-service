"""Internal MCP assertions are trusted only from registered callers with their own RS256 key."""

import time
import uuid

import jwt
from django.test import TestCase, override_settings
from shellui_django.mcp.internal import (
    REVOCATION_AUDIENCE,
    REVOCATION_SCOPE,
    build_mcp_approval_assertion,
    build_mcp_revocation_assertion,
)

from apps.agents.tests.mcp_test_settings import (
    TEST_CALLER_ISSUER,
    TEST_CALLER_SIGNING,
    TRUSTED_TEST_CALLER_SETTINGS,
    rs256_identity_settings,
)
from apps.authapi.jwks import generate_rsa_key_pair

IDENTITY_ORIGIN = 'https://identity.test'
REVOCATIONS = '/api/v1/mcp/internal/mcp-revocations'
APPROVALS = '/api/v1/mcp/internal/mcp-approval-requests'


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER=IDENTITY_ORIGIN,
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpInternalCallerTests(TestCase):
    def _revocations(self, assertion):
        return self.client.get(REVOCATIONS, HTTP_AUTHORIZATION=f'Bearer {assertion}')

    def test_registered_caller_is_accepted(self):
        assertion = build_mcp_revocation_assertion(audience_url=IDENTITY_ORIGIN, **TEST_CALLER_SIGNING)
        with rs256_identity_settings():
            self.assertEqual(self._revocations(assertion).status_code, 200)

    def test_unregistered_issuer_is_rejected(self):
        signing = {**TEST_CALLER_SIGNING, 'issuer': 'https://attacker.test'}
        assertion = build_mcp_revocation_assertion(audience_url=IDENTITY_ORIGIN, **signing)
        self.assertEqual(self._revocations(assertion).status_code, 401)

    def test_caller_without_issuer_setting_is_not_trusted(self):
        assertion = build_mcp_revocation_assertion(audience_url=IDENTITY_ORIGIN, **TEST_CALLER_SIGNING)
        with override_settings(STORAGE_SERVICE_ISSUER=''):
            self.assertEqual(self._revocations(assertion).status_code, 401)

    def test_registered_issuer_with_other_key_is_rejected(self):
        other_private, _ = generate_rsa_key_pair(2048)
        signing = {**TEST_CALLER_SIGNING, 'private_key_pem': other_private}
        assertion = build_mcp_revocation_assertion(audience_url=IDENTITY_ORIGIN, **signing)
        self.assertEqual(self._revocations(assertion).status_code, 401)

    def test_hs256_assertion_is_rejected(self):
        now = int(time.time())
        claims = {
            'iss': TEST_CALLER_ISSUER,
            'aud': REVOCATION_AUDIENCE,
            'sub': 'service',
            'scope': REVOCATION_SCOPE,
            'target': IDENTITY_ORIGIN,
            'iat': now,
            'exp': now + 60,
            'jti': uuid.uuid4().hex,
        }
        assertion = jwt.encode(claims, 'shared-secret-not-a-key-0123456789abcdef', algorithm='HS256')
        self.assertEqual(self._revocations(assertion).status_code, 401)

    def test_replayed_assertion_is_rejected(self):
        assertion = build_mcp_revocation_assertion(audience_url=IDENTITY_ORIGIN, **TEST_CALLER_SIGNING)
        with rs256_identity_settings():
            self.assertEqual(self._revocations(assertion).status_code, 200)
            self.assertEqual(self._revocations(assertion).status_code, 401)

    def test_caller_cannot_request_approval_for_another_service(self):
        assertion = build_mcp_approval_assertion(
            **TEST_CALLER_SIGNING,
            company_id=1,
            agent_id=str(uuid.uuid4()),
            service='hosting',
            action='write_tool',
            arguments_hash='abc123',
            audience_url=IDENTITY_ORIGIN,
        )
        response = self.client.post(
            APPROVALS,
            data='{}',
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900)
    def test_storage_service_cannot_use_extended_approval_lifetime(self):
        assertion = build_mcp_approval_assertion(
            **TEST_CALLER_SIGNING,
            company_id=1,
            agent_id=str(uuid.uuid4()),
            service='storage',
            action='write_tool',
            arguments_hash='abc999',
            audience_url=IDENTITY_ORIGIN,
            lifetime_seconds=900,
        )
        response = self.client.post(
            APPROVALS,
            data='{}',
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {assertion}',
        )
        self.assertEqual(response.status_code, 401)
