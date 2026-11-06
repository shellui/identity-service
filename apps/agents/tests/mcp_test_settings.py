"""Shared Django settings helpers for MCP integration tests."""

from __future__ import annotations

from contextlib import contextmanager

from django.test import override_settings

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
