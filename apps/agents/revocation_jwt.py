"""Signed MCP revocation list responses with policy version for gateway cache invalidation."""

from __future__ import annotations

import time
import uuid
from typing import Any

from django.conf import settings
from shellui_django.mcp.internal import (
    REVOCATION_AUDIENCE,
    REVOCATION_LIST_ASSERTION_LIFETIME_SECONDS,
    REVOCATION_LIST_SCOPE,
)

from apps.federation.signing import issuer, sign_rs256

REVOCATION_POLICY_VERSION_EPOCH_MS = 17_000_000_000_000


def compute_revocation_policy_version(
    *,
    revoked_ids: list[str],
    agents: list[dict[str, Any]],
    cache_seconds: int,
    max_active_permission_version: int,
) -> int:
    """
    Fingerprint for positive gateway cache: changes when block list or agent snapshots change.

    Uses a stable hash over ids, per-agent permission_version on blocked rows, the global
    max active permission_version (grant invalidation without agent pause), and cache_seconds.
    """
    import hashlib

    parts: list[str] = []
    for aid in sorted(revoked_ids):
        parts.append(aid)
    for row in sorted(agents, key=lambda r: str(r.get('agent_id', ''))):
        parts.append(str(row.get('agent_id', '')))
        parts.append(str(row.get('company_id', '')))
        parts.append(str(row.get('permission_version', 0)))
    parts.append(str(int(max_active_permission_version)))
    parts.append(str(cache_seconds))
    digest = hashlib.sha256('|'.join(parts).encode()).hexdigest()[:16]
    return REVOCATION_POLICY_VERSION_EPOCH_MS + int(digest, 16) % 1_000_000_000_000


def sign_revocation_list_response(
    *,
    revoked_agent_ids: list[str],
    agents: list[dict[str, Any]],
    cache_seconds: int,
    revocation_policy_version: int,
) -> str:
    """RS256 JWT: same audience/scope as shellui ``build_mcp_revocation_list_response_assertion`` plus policy version."""
    now = int(time.time())
    claims: dict[str, Any] = {
        'iss': (issuer() or '').strip().rstrip('/'),
        'aud': REVOCATION_AUDIENCE,
        'sub': 'identity',
        'scope': REVOCATION_LIST_SCOPE,
        'revoked_agent_ids': [str(item) for item in revoked_agent_ids],
        'agents': agents,
        'cache_seconds': int(cache_seconds),
        'revocation_policy_version': int(revocation_policy_version),
        'iat': now,
        'exp': now + REVOCATION_LIST_ASSERTION_LIFETIME_SECONDS,
        'jti': uuid.uuid4().hex,
    }
    return sign_rs256(claims)
