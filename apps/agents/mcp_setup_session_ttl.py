"""Trusted session Allow TTL during new-company setup (ai-service assertions only)."""

from __future__ import annotations

from django.conf import settings


def _truthy_setup_flow(raw) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in ('1', 'true', 'yes', 'setup', 'setup_flow', 'new_company')
    return False


def trusted_setup_mcp_session_ttl_seconds_from_claims(claims: dict) -> int | None:
    """Return signed mcp_session_ttl_seconds when setup_flow is set; otherwise None."""
    if not _truthy_setup_flow(claims.get('setup_flow')):
        return None
    raw = claims.get('mcp_session_ttl_seconds')
    try:
        ttl = int(raw)
    except (TypeError, ValueError):
        return None
    if ttl <= 0:
        return None
    return ttl


def session_allow_ttl_bound_seconds() -> tuple[int, int]:
    """Min and max seconds for an extended setup session grant (from settings)."""
    lo = int(getattr(settings, 'MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS', 600) or 600)
    hi = int(getattr(settings, 'MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS', 900) or 900)
    if lo > hi:
        lo, hi = hi, lo
    return lo, hi


def resolve_session_grant_ttl_seconds(
    *,
    caller_name: str,
    assertion_claims: dict | None,
) -> int:
    """
    Session Allow TTL: default from MCP_APPROVAL_SESSION_TTL_SECONDS (30 to 60 unless extended).

    Extended 600 to 900 seconds only for assertions from ai-service (trusted gateway) with
    ``setup_flow`` truthy and ``mcp_session_ttl_seconds`` in the signed JWT within the
    configured setup band (and not above the assertion lifetime).
    """
    base = int(getattr(settings, 'MCP_APPROVAL_SESSION_TTL_SECONDS', 60) or 60)
    base = max(30, min(base, 60))

    if caller_name != 'ai':
        return base

    setup_ttl = trusted_setup_mcp_session_ttl_seconds_from_claims(assertion_claims or {})
    if setup_ttl is None:
        return base

    lo, hi = session_allow_ttl_bound_seconds()
    if setup_ttl < lo or setup_ttl > hi:
        return base

    max_from_assertion = None
    try:
        iat = int(assertion_claims.get('iat'))
        exp = int(assertion_claims.get('exp'))
        if exp > iat:
            max_from_assertion = exp - iat
    except (TypeError, ValueError, KeyError):
        pass

    if max_from_assertion is not None and setup_ttl > max_from_assertion:
        return base

    return setup_ttl
