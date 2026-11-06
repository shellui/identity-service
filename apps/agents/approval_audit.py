"""Audit events for MCP approval decisions."""

from __future__ import annotations

from apps.actions.event_log import record_event
from apps.actions.registry import get_event_type
from apps.agents.models import McpApprovalRequest
from apps.federation.models import ProvisionedCompany

APPROVAL_AUDIT_APPROVED = 'approved'
APPROVAL_AUDIT_DENIED = 'denied'
APPROVAL_AUDIT_EXPIRED = 'expired'
APPROVAL_AUDIT_CLIENT_ALLOWED = 'client_allowed'
APPROVAL_AUDIT_CLIENT_DENIED = 'client_denied'
APPROVAL_AUDIT_CLIENT_SESSION_ALLOWED = 'client_session_allowed'


def _audit_company_for_row(row: McpApprovalRequest):
    if row.company_id is not None:
        return row.company
    if row.global_company_id is None:
        return None
    pc = (
        ProvisionedCompany.objects.filter(global_company_id=str(row.global_company_id))
        .select_related('company')
        .first()
    )
    return pc.company if pc is not None else None


def record_approval_decision_event(
    row: McpApprovalRequest,
    *,
    status: str,
    actor_email: str | None,
    user=None,
) -> None:
    event = get_event_type('identity.mcp.approval_decision')
    if event is None:
        return
    tool_name = row.action
    agent_name = row.agent.name if row.agent_id is not None else 'Global control plane'
    email = (actor_email or '').strip() or None
    record_event(
        event,
        _audit_company_for_row(row),
        {
            'approval_id': str(row.id),
            'actor_email': email,
            'status': status,
            'tool_name': tool_name,
            'agent_name': agent_name,
            'service': row.service,
        },
        user=user,
    )


def record_approval_expired_once(row: McpApprovalRequest) -> None:
    if row.expired_event_logged:
        return
    record_approval_decision_event(row, status=APPROVAL_AUDIT_EXPIRED, actor_email=None)
    row.expired_event_logged = True
    row.save(update_fields=['expired_event_logged'])
