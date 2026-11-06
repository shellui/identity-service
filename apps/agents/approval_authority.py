"""Live authority binding for MCP internal approval assertions (gateway-signed JWT)."""

from __future__ import annotations

import uuid
from typing import Any

from apps.agents.models import Agent


def parse_approval_authority_claims(claims: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """
    Required in the approval assertion JWT: ``grant_version`` (int).

    When the regional ``Agent`` has ``global_company_id`` set, the assertion must also carry
    ``global_company_id`` (uuid string) and ``company_binding_version`` (int) matching the agent.
    """
    raw_gv = claims.get('grant_version')
    if raw_gv is None or raw_gv == '':
        return None, 'grant_version required in assertion.'
    try:
        grant_version = int(raw_gv)
    except (TypeError, ValueError):
        return None, 'Invalid grant_version.'
    if grant_version < 0:
        return None, 'Invalid grant_version.'

    raw_gc = claims.get('global_company_id')
    global_company_id: uuid.UUID | None
    if raw_gc is None or raw_gc == '':
        global_company_id = None
    else:
        try:
            global_company_id = uuid.UUID(str(raw_gc))
        except (ValueError, TypeError):
            return None, 'Invalid global_company_id.'

    raw_cb = claims.get('company_binding_version')
    company_binding_version: int | None
    if raw_cb is None or raw_cb == '':
        company_binding_version = None
    else:
        try:
            company_binding_version = int(raw_cb)
        except (TypeError, ValueError):
            return None, 'Invalid company_binding_version.'
        if company_binding_version < 0:
            return None, 'Invalid company_binding_version.'

    return (
        {
            'grant_version': grant_version,
            'global_company_id': global_company_id,
            'company_binding_version': company_binding_version,
        },
        None,
    )


def agent_matches_approval_authority(agent: Agent, auth: dict[str, Any]) -> bool:
    if int(agent.grant_version or 0) != int(auth['grant_version']):
        return False
    agc = getattr(agent, 'global_company_id', None)
    if agc is not None:
        if auth['global_company_id'] is None:
            return False
        if agc != auth['global_company_id']:
            return False
        cb = getattr(agent, 'company_binding_version', None)
        if cb is None or auth['company_binding_version'] is None:
            return False
        if int(cb) != int(auth['company_binding_version']):
            return False
    return True


def approval_row_stale_for_agent(agent: Agent, row) -> bool:
    """True when the row was created under an older grant or SaaS binding than the current agent."""
    from apps.agents.models import McpApprovalRequest

    if not isinstance(row, McpApprovalRequest):
        return True
    if int(getattr(agent, 'grant_version', 0) or 0) != int(getattr(row, 'authority_grant_version', 0) or 0):
        return True
    ag_gc = getattr(agent, 'global_company_id', None)
    row_gc = getattr(row, 'authority_global_company_id', None)
    if ag_gc is None and row_gc is None:
        return False
    if ag_gc is None or row_gc is None:
        return True
    if ag_gc != row_gc:
        return True
    ag_cb = getattr(agent, 'company_binding_version', None)
    row_cb = getattr(row, 'authority_company_binding_version', None)
    if ag_cb is None and row_cb is None:
        return False
    if ag_cb is None or row_cb is None:
        return True
    return int(ag_cb) != int(row_cb)
