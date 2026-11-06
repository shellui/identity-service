"""Trusted session Allow TTL during new-company setup (ai-service assertions only)."""

from __future__ import annotations

from django.conf import settings
from django.utils import timezone

from apps.agents.models import Agent


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
    agent: Agent,
    now=None,
) -> int:
    """
    Session Allow TTL: default from MCP_APPROVAL_SESSION_TTL_SECONDS (30 to 60 unless extended).

    Extended 600 to 900 seconds only for assertions from ai-service (trusted gateway) with
    ``setup_flow`` truthy and ``mcp_session_ttl_seconds`` in the signed JWT within the
    configured setup band (and not above the assertion lifetime).

    Additionally requires a server-authorized per-company setup window on the regional
    ``Agent`` (``setup_company_id`` matches this company and ``setup_context_expires_at``
    is in the future), copied from the global subject token at token exchange. Without
    that row state, setup claims in the gateway assertion are ignored.

    The extended band applies only when both remaining time to access token ``exp`` and
    remaining time to ``setup_context_expires_at`` are at least ``lo`` (600 by default);
    otherwise this falls back to ``base`` (typically 60 seconds). The grant never outlives
    the minimum of those deadlines.
    """
    base = int(getattr(settings, 'MCP_APPROVAL_SESSION_TTL_SECONDS', 60) or 60)
    base = max(30, min(base, 60))

    if caller_name != 'ai':
        return base

    claims = assertion_claims or {}
    setup_ttl = trusted_setup_mcp_session_ttl_seconds_from_claims(claims)
    if setup_ttl is None:
        return base

    lo, hi = session_allow_ttl_bound_seconds()
    if setup_ttl < lo or setup_ttl > hi:
        return base

    max_from_assertion = None
    remaining_from_jwt = None
    try:
        iat = int(claims.get('iat'))
        exp = int(claims.get('exp'))
        if exp > iat:
            max_from_assertion = exp - iat
    except (TypeError, ValueError, KeyError):
        pass

    if now is None:
        now = timezone.now()
    try:
        exp = int(claims.get('exp'))
        remaining_from_jwt = float(exp) - now.timestamp()
    except (TypeError, ValueError, KeyError):
        pass

    if max_from_assertion is not None and setup_ttl > max_from_assertion:
        return base

    ctx_until = getattr(agent, 'setup_context_expires_at', None)
    ctx_company = getattr(agent, 'setup_company_id', None)
    if (
        ctx_until is None
        or ctx_company is None
        or int(ctx_company) != int(agent.company_id)
        or ctx_until <= now
    ):
        return base

    remaining_setup = (ctx_until - now).total_seconds()
    if remaining_setup <= 0:
        return base

    ceiling_candidates = [remaining_setup, float(hi)]
    if remaining_from_jwt is not None:
        ceiling_candidates.append(remaining_from_jwt)
    ceiling = min(ceiling_candidates)

    # Do not sign a long setup grant when the shorter of token or setup window is under the band.
    if ceiling < float(lo):
        return base

    capped = min(float(setup_ttl), ceiling)
    return max(30, int(capped))
