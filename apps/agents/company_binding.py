"""Verify SaaS (dashboard) company-binding delegation JWTs on regional agent token exchange."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from typing import Any

import jwt
from django.conf import settings

from apps.federation.provisioning import provisioning_audience
from apps.federation.signing import CLOCK_SKEW, TokenError

DELEGATION_SCOPE = 'mcp.company_binding.delegate'


@dataclass(frozen=True)
class CompanyBindingDelegation:
    """Verified delegation claims for one exchange."""

    global_user_sub: str
    regional_company_id: int
    global_company_id: uuid.UUID
    company_binding_version: int
    global_agent_id: uuid.UUID
    is_company_owner: bool
    setup_expires_at: datetime | None
    mcp_access: str | None
    mcp_read: str | None
    mcp_destructive: bool | None
    services: list[str] | None


def _parse_uuid(raw) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(raw))
    except (TypeError, ValueError):
        return None


def verify_company_binding_assertion(
    raw_token: str | None,
    *,
    expected_sub: str,
    expected_regional_company_id: int,
    expected_global_agent_id: uuid.UUID,
) -> CompanyBindingDelegation | None:
    """Return parsed delegation or None when absent. Raises TokenError on invalid token when present."""
    token = (raw_token or '').strip()
    if not token:
        return None
    pem = (getattr(settings, 'PROVISIONING_PUBLIC_KEY', '') or '').strip()
    issuer = (getattr(settings, 'PROVISIONING_ISSUER', '') or '').strip()
    if not pem or not issuer:
        raise TokenError('delegation_not_configured')
    audience = (getattr(settings, 'COMPANY_BINDING_DELEGATION_AUDIENCE', '') or '').strip() or provisioning_audience()
    try:
        claims = jwt.decode(
            token,
            pem,
            algorithms=['RS256'],
            audience=audience,
            issuer=issuer,
            leeway=CLOCK_SKEW,
            options={'require': ['exp', 'iat', 'iss', 'aud', 'sub', 'jti']},
        )
    except jwt.InvalidTokenError as exc:
        raise TokenError('invalid_delegation') from exc

    if str(claims.get('scope') or '') != DELEGATION_SCOPE:
        raise TokenError('invalid_delegation_scope')

    sub = str(claims.get('sub') or '')
    if sub != expected_sub:
        raise TokenError('delegation_sub_mismatch')

    try:
        cid = int(claims.get('company_id'))
    except (TypeError, ValueError):
        raise TokenError('invalid_delegation')
    if cid != expected_regional_company_id:
        raise TokenError('delegation_company_mismatch')

    gid = _parse_uuid(claims.get('global_agent_id'))
    if gid is None or gid != expected_global_agent_id:
        raise TokenError('delegation_agent_mismatch')

    gcomp = _parse_uuid(claims.get('global_company_id'))
    if gcomp is None:
        raise TokenError('invalid_delegation')

    try:
        ver = int(claims.get('company_binding_version'))
    except (TypeError, ValueError):
        raise TokenError('invalid_delegation')
    if ver < 1:
        raise TokenError('invalid_delegation')

    owner_raw = claims.get('is_company_owner')
    if isinstance(owner_raw, bool):
        is_owner = owner_raw
    else:
        is_owner = str(owner_raw or '').strip().lower() in ('1', 'true', 'yes')

    setup_exp = None
    raw_exp = claims.get('setup_expires_at')
    try:
        if raw_exp is not None:
            ts = int(raw_exp)
            if ts > int(claims.get('iat') or 0):
                setup_exp = datetime.fromtimestamp(ts, tz=dt_timezone.utc)
    except (TypeError, ValueError):
        pass

    services = None
    raw_sv = claims.get('services')
    if isinstance(raw_sv, list):
        services = [str(s) for s in raw_sv if s]
    elif isinstance(raw_sv, str) and raw_sv.strip():
        services = [p for p in raw_sv.split() if p]

    mcp_acc = claims.get('mcp_access')
    mcp_acc = str(mcp_acc) if mcp_acc is not None else None
    mcp_rd = claims.get('mcp_read')
    mcp_rd = str(mcp_rd) if mcp_rd is not None else None
    dest = claims.get('mcp_destructive')
    if isinstance(dest, bool):
        mcp_dest = dest
    elif dest is None:
        mcp_dest = None
    else:
        mcp_dest = str(dest).strip().lower() in ('1', 'true', 'yes')

    return CompanyBindingDelegation(
        global_user_sub=sub,
        regional_company_id=cid,
        global_company_id=gcomp,
        company_binding_version=ver,
        global_agent_id=gid,
        is_company_owner=is_owner,
        setup_expires_at=setup_exp,
        mcp_access=mcp_acc,
        mcp_read=mcp_rd,
        mcp_destructive=mcp_dest,
        services=services,
    )
