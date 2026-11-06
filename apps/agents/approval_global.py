"""Helpers for account-scope (global) MCP approvals stored on the region."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone as dt_timezone
from typing import Any

from django.utils import timezone

from apps.agents.models import Agent, McpApprovalRequest
from apps.agents.global_revocation import global_agent_exchange_blocked


GLOBAL_PLACEHOLDER_COMPANY_ID = 0


def is_global_placeholder_company_id(company_id: int | None) -> bool:
    return company_id is not None and int(company_id) == GLOBAL_PLACEHOLDER_COMPANY_ID


def parse_uuid(raw: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(raw))
    except (TypeError, ValueError):
        return None


def parse_setup_expires_at_unix(raw: Any) -> datetime | None:
    try:
        ts = int(raw)
    except (TypeError, ValueError):
        return None
    if ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=dt_timezone.utc)


def global_agent_revoked(global_agent_id: uuid.UUID | None) -> bool:
    if global_agent_id is None:
        return True
    return global_agent_exchange_blocked(global_agent_id)


def ensure_global_approval_claims(claims: dict[str, Any]) -> dict[str, Any] | None:
    """Validate dashboard-forwarded global approval assertion claims."""
    ga = parse_uuid(claims.get('global_agent_id'))
    gc = parse_uuid(claims.get('global_company_id'))
    if ga is None or gc is None:
        return None
    raw_ver = claims.get('company_binding_version')
    try:
        ver = int(raw_ver)
    except (TypeError, ValueError):
        return None
    if ver < 1:
        return None
    raw_setup = claims.get('setup_expires_at')
    setup_exp = parse_setup_expires_at_unix(raw_setup) if raw_setup is not None else None
    if raw_setup is not None and setup_exp is None:
        return None
    if setup_exp is not None and setup_exp <= timezone.now():
        return None
    gsub = str(claims.get('global_user_sub') or claims.get('sub') or '').strip()
    if not gsub:
        return None

    owner_raw = claims.get('is_company_owner')
    if isinstance(owner_raw, bool):
        is_owner = owner_raw
    else:
        is_owner = str(owner_raw or '').strip().lower() in ('1', 'true', 'yes')
    return {
        'global_agent_id': ga,
        'global_company_id': gc,
        'company_binding_version': ver,
        'setup_expires_at': setup_exp,
        'is_company_owner': is_owner,
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


def user_trusted_for_global_approval(
    user,
    *,
    global_company_id: uuid.UUID,
    is_company_owner: bool,
) -> bool:
    """Fallback: global SaaS forwarded owner flag (dashboard assertions only)."""
    return is_company_owner
