"""Shared Django settings helpers for MCP integration tests."""

from __future__ import annotations

import time
import uuid
from contextlib import contextmanager

import jwt
from django.conf import settings
from django.test import override_settings
from shellui_django.mcp.internal import APPROVAL_AUDIENCE, APPROVAL_SCOPE

from apps.authapi.jwks import build_jwks_document, generate_rsa_key_pair, load_signing_key


@contextmanager
def rs256_identity_settings():
    private, public = generate_rsa_key_pair(2048)
    signing = load_signing_key(private_pem=private, public_pem=public)
    jwks = build_jwks_document(signing)
    with override_settings(
        JWT_SIGNING_KEY=signing,
        JWT_ACTIVE_KEY_ID=signing.kid,
        JWT_ALGORITHM='RS256',
        JWKS_ENABLED=True,
    ):
        yield signing, jwks


# One RS256 key standing in for storage-service, a caller registered in internal_callers.
_CALLER_PRIVATE, _CALLER_PUBLIC = generate_rsa_key_pair(2048)
_CALLER_KEY = load_signing_key(private_pem=_CALLER_PRIVATE, public_pem=_CALLER_PUBLIC)
TEST_CALLER_ISSUER = 'https://storage.test'
TRUSTED_TEST_CALLER_SETTINGS = {
    'STORAGE_SERVICE_ISSUER': TEST_CALLER_ISSUER,
    'STORAGE_SERVICE_JWKS': build_jwks_document(_CALLER_KEY),
}
# Keyword arguments for shellui_django ``build_mcp_*_assertion`` helpers.
TEST_CALLER_SIGNING = {
    'private_key_pem': _CALLER_KEY.private_pem,
    'kid': _CALLER_KEY.kid,
    'issuer': TEST_CALLER_ISSUER,
}

# RS256 key standing in for ai-service (MCP gateway) approval assertions.
_AI_PRIVATE, _AI_PUBLIC = generate_rsa_key_pair(2048)
_AI_KEY = load_signing_key(private_pem=_AI_PRIVATE, public_pem=_AI_PUBLIC)
TEST_AI_SERVICE_ISSUER = 'https://ai.test'
TRUSTED_AI_TEST_CALLER_SETTINGS = {
    'AI_SERVICE_ISSUER': TEST_AI_SERVICE_ISSUER,
    'AI_SERVICE_URL': 'https://ai.example.com',
    'AI_SERVICE_JWKS': build_jwks_document(_AI_KEY),
}
TEST_AI_CALLER_SIGNING = {
    'private_key_pem': _AI_KEY.private_pem,
    'kid': _AI_KEY.kid,
    'issuer': TEST_AI_SERVICE_ISSUER,
}


def authority_claims_for_agent(agent) -> dict:
    """Claims the gateway must embed in MCP approval assertions (live authority binding)."""
    claims = {'grant_version': int(getattr(agent, 'grant_version', 0) or 0)}
    gc = getattr(agent, 'global_company_id', None)
    if gc is not None:
        claims['global_company_id'] = str(gc)
        claims['company_binding_version'] = int(getattr(agent, 'company_binding_version', 0) or 0)
    return claims


def approval_authority_snapshot_for_agent(agent) -> dict:
    """ORM defaults for ``McpApprovalRequest`` authority snapshot fields."""
    snap = {
        'authority_grant_version': int(getattr(agent, 'grant_version', 0) or 0),
        'authority_global_company_id': getattr(agent, 'global_company_id', None),
        'authority_company_binding_version': getattr(agent, 'company_binding_version', None),
    }
    return snap


def _approval_service_issuer(explicit: str | None) -> str:
    if explicit and str(explicit).strip():
        return str(explicit).strip().rstrip('/')
    return str(getattr(settings, 'JWT_ISSUER', '') or '').strip().rstrip('/')


def build_mcp_approval_assertion_for_agent(
    agent,
    *,
    company_id: int,
    agent_id: str,
    service: str,
    action: str,
    arguments_hash: str,
    audience_url: str,
    lifetime_seconds: int = 60,
    private_key_pem: str | None = None,
    kid: str | None = None,
    issuer: str | None = None,
    authority_claims_override: dict | None = None,
) -> str:
    """Same shape as ``shellui_django`` ``build_mcp_approval_assertion`` plus live authority claims."""
    now = int(time.time())
    auth = {**authority_claims_for_agent(agent)}
    if authority_claims_override:
        auth.update(authority_claims_override)
    claims = {
        'iss': _approval_service_issuer(issuer),
        'aud': APPROVAL_AUDIENCE,
        'sub': f'agent:{agent_id}',
        'scope': APPROVAL_SCOPE,
        'company_id': company_id,
        'agent_id': agent_id,
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
        'target': audience_url,
        'iat': now,
        'exp': now + int(lifetime_seconds),
        'jti': uuid.uuid4().hex,
        **auth,
    }
    token = jwt.encode(claims, private_key_pem, algorithm='RS256', headers={'kid': kid} if kid else None)
    return token.decode('utf-8') if isinstance(token, bytes) else token
