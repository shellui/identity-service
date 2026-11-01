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
