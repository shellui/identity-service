"""Verify Identity-signed MCP revocation poll payloads (for tests and local mirrors of shellui parsing)."""

from __future__ import annotations

import json
from typing import Any

import jwt
from django.conf import settings
from jwt.algorithms import RSAAlgorithm
from shellui_django.mcp.internal import REVOCATION_AUDIENCE, REVOCATION_LIST_SCOPE

from apps.federation.signing import CLOCK_SKEW, public_jwks


def parse_trusted_revocation_poll_response_identity(
    body: dict[str, Any],
    *,
    expected_issuer: str,
    jwks: dict[str, Any] | None = None,
) -> tuple[frozenset[str], int, list[dict[str, Any]], int]:
    """
    Verify ``revocation_assertion`` and return (revoked_ids, cache_seconds, agents, revocation_policy_version).

    ``jwks`` defaults to Identity deployment keys (same as ``/.well-known/jwks.json``).
    """
    assertion = str(body.get('revocation_assertion') or '').strip()
    if not assertion:
        raise ValueError('Missing revocation_assertion')
    document = jwks if jwks is not None else public_jwks()
    keys = document.get('keys') if isinstance(document, dict) else None
    if not isinstance(keys, list) or not keys:
        raise ValueError('JWKS is empty')
    header = jwt.get_unverified_header(assertion)
    kid = header.get('kid')
    jwk = next((k for k in keys if isinstance(k, dict) and k.get('kid') == kid), None)
    if jwk is None:
        raise ValueError('Unknown signing key')
    public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    claims = jwt.decode(
        assertion,
        public_key,
        algorithms=['RS256'],
        audience=REVOCATION_AUDIENCE,
        issuer=expected_issuer.rstrip('/'),
        leeway=CLOCK_SKEW,
        options={'require': ['exp', 'iat', 'iss', 'aud', 'revocation_policy_version']},
    )
    if claims.get('scope') != REVOCATION_LIST_SCOPE:
        raise ValueError('Invalid revocation list scope')
    raw_ids = claims.get('revoked_agent_ids') or []
    if not isinstance(raw_ids, list):
        raise ValueError('Invalid revoked_agent_ids')
    agents = claims.get('agents')
    if agents is not None and not isinstance(agents, list):
        raise ValueError('Invalid agents')
    cache = int(claims.get('cache_seconds') or body.get('cache_seconds') or 0)
    policy_ver = int(claims['revocation_policy_version'])
    revoked_frozen = frozenset(str(x) for x in raw_ids)
    return revoked_frozen, cache, list(agents or []), policy_ver
