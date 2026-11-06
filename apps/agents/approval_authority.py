"""Live authority binding for MCP internal approval assertions (gateway-signed JWT)."""

from __future__ import annotations

import uuid
from typing import Any

from apps.agents.json_strict import strict_non_negative_int
from apps.agents.models import Agent


def parse_approval_authority_claims(claims: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """
    Required in the approval assertion JWT: ``grant_version`` (JSON integer).

    When present, ``global_company_id`` must be a uuid string and ``company_binding_version`` a JSON integer
    (``0`` is valid). String numerics and other loose types are rejected.
    """
    raw_gv = claims.get('grant_version')
    gv = strict_non_negative_int(raw_gv)
    if gv is None:
        return None, 'grant_version required in assertion.'
    grant_version = gv

    raw_gc = claims.get('global_company_id')
    global_company_id: uuid.UUID | None
    if raw_gc is None or raw_gc == '':
        global_company_id = None
    else:
        if type(raw_gc) is not str or not raw_gc.strip():
            return None, 'global_company_id must be a uuid string or absent.'
        try:
            global_company_id = uuid.UUID(raw_gc.strip())
        except (ValueError, TypeError):
            return None, 'Invalid global_company_id.'

    raw_cb = claims.get('company_binding_version')
    company_binding_version: int | None
    if raw_cb is None or raw_cb == '':
        company_binding_version = None
    else:
        cb = strict_non_negative_int(raw_cb)
        if cb is None:
            return None, 'company_binding_version must be a JSON integer or absent.'
        company_binding_version = cb

    if global_company_id is not None and company_binding_version is None:
        return None, 'company_binding_version required when global_company_id is present.'
    if company_binding_version is not None and global_company_id is None:
        return None, 'global_company_id required when company_binding_version is present.'

    return (
        {
            'grant_version': grant_version,
            'global_company_id': global_company_id,
            'company_binding_version': company_binding_version,
        },
        None,
    )


def agent_matches_approval_authority(agent: Agent, auth: dict[str, Any]) -> bool:
    row_gv = getattr(agent, 'grant_version', None)
    if (row_gv if row_gv is not None else 0) != auth['grant_version']:
        return False
    agc = getattr(agent, 'global_company_id', None)
    agcb = getattr(agent, 'company_binding_version', None)
    auth_gc = auth['global_company_id']
    auth_cb = auth['company_binding_version']
    # Delegated (company-bound): assertion must carry the full SaaS binding triple.
    if agc is not None:
        if auth_gc is None or auth_cb is None:
            return False
        if agc != auth_gc:
            return False
        if agcb is None:
            return False
        if agcb != auth_cb:
            return False
        return True
    if auth_gc is not None or auth_cb is not None:
        return False
    return True


def approval_row_stale_for_agent(agent: Agent, row) -> bool:
    """True when the row was created under an older grant or SaaS binding than the current agent."""
    from apps.agents.models import McpApprovalRequest

    if not isinstance(row, McpApprovalRequest):
        return True
    agv = getattr(agent, 'grant_version', None)
    rv = getattr(row, 'authority_grant_version', None)
    if (agv if agv is not None else 0) != (rv if rv is not None else 0):
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
    return ag_cb != row_cb
