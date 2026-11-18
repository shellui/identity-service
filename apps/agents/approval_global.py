"""Helpers for account-scope (global) MCP approvals stored on the region."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone as dt_timezone
from typing import Any

from django.conf import settings
from django.utils import timezone

from apps.agents.json_strict import strict_non_negative_int
from apps.agents.models import Agent, McpApprovalRequest
from apps.agents.global_revocation import global_agent_exchange_blocked
from apps.companies.models import Company
from apps.federation.models import ProvisionedCompany, UpstreamAccount


GLOBAL_PLACEHOLDER_COMPANY_ID = 0


def is_global_placeholder_company_id(company_id: int | None) -> bool:
    return company_id is not None and int(company_id) == GLOBAL_PLACEHOLDER_COMPANY_ID


def parse_uuid(raw: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(raw))
    except (TypeError, ValueError):
        return None


def parse_setup_expires_at_unix(raw: Any) -> datetime | None:
    ts = strict_non_negative_int(raw)
    if ts is None or ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=dt_timezone.utc)


def global_agent_revoked(global_agent_id: uuid.UUID | None) -> bool:
    if global_agent_id is None:
        return True
    return global_agent_exchange_blocked(global_agent_id)


def ensure_global_approval_claims(claims: dict[str, Any]) -> dict[str, Any] | None:
    """Validate global-scope approval assertion claims (company_id=0 placeholder).

    Requires explicit ``global_user_sub`` (global IdP subject). Identity does not trust a forwarded
    ``is_company_owner`` flag; owner checks use ``UpstreamAccount`` + regional ``Company.owners``.
    """
    ga = parse_uuid(claims.get('global_agent_id'))
    gc = parse_uuid(claims.get('global_company_id'))
    if ga is None or gc is None:
        return None
    raw_ver = claims.get('company_binding_version')
    ver = strict_non_negative_int(raw_ver)
    if ver is None:
        return None
    raw_setup = claims.get('setup_expires_at')
    setup_exp = parse_setup_expires_at_unix(raw_setup) if raw_setup is not None else None
    if raw_setup is not None and setup_exp is None:
        return None
    if setup_exp is not None and setup_exp <= timezone.now():
        return None
    gsub = str(claims.get('global_user_sub') or '').strip()
    if not gsub:
        return None
    return {
        'global_agent_id': ga,
        'global_company_id': gc,
        'company_binding_version': ver,
        'setup_expires_at': setup_exp,
        'global_user_sub': gsub,
    }


def link_global_approval_to_regional_agent(row: McpApprovalRequest, agent: Agent) -> None:
    """Attach a global approval row to a regional agent after provisioning."""
    if row.global_agent_id is None or row.agent_id is not None:
        return
    if parse_uuid(str(agent.global_agent_id)) != row.global_agent_id:
        return
    if row.global_company_id and agent.global_company_id and row.global_company_id != agent.global_company_id:
        return
    if row.company_binding_version and agent.company_binding_version:
        if row.company_binding_version != agent.company_binding_version:
            return
    row.agent = agent
    row.company = agent.company
    row.save(update_fields=['agent', 'company'])


def _global_issuer() -> str:
    return (getattr(settings, 'GLOBAL_ISSUER_URL', '') or '').strip().rstrip('/')


def provisioned_company_for_global_uuid(global_company_id: uuid.UUID) -> ProvisionedCompany | None:
    """Regional company row provisioned for this SaaS global id."""
    return (
        ProvisionedCompany.objects.select_related('company')
        .filter(global_company_id=str(global_company_id))
        .first()
    )


def global_user_sub_is_company_owner(*, global_user_sub: str, company: Company) -> bool:
    """True when ``global_user_sub`` is the global IdP subject for a regional company owner."""
    issuer = _global_issuer()
    if not issuer:
        return False
    link = UpstreamAccount.objects.filter(issuer=issuer, sub=global_user_sub).select_related('user').first()
    if link is None:
        return False
    return company.owners.filter(pk=link.user_id).exists()


def global_approval_live_binding_ok(meta: dict[str, Any], *, authority_grant_version: int) -> bool:
    """``company_binding_version`` and ``grant_version`` in the assertion match provisioned state."""
    gc = meta.get('global_company_id')
    if not isinstance(gc, uuid.UUID):
        return False
    cb = meta.get('company_binding_version')
    if not isinstance(cb, int) or cb < 0:
        return False
    pc = provisioned_company_for_global_uuid(gc)
    if pc is None:
        return False
    if int(pc.limits_version) != int(cb):
        return False
    if int(pc.limits_version) != int(authority_grant_version):
        return False
    return True
