"""Shared MCP approval lookup and consume binding (internal API + Identity /mcp)."""

from __future__ import annotations

from typing import Any

from django.utils import timezone

from apps.agents.models import McpApprovalRequest


def approval_binding_from_claims(claims: dict[str, Any]) -> dict[str, Any] | None:
    agent_id = str(claims.get('agent_id') or '')
    company_id = claims.get('company_id')
    service = str(claims.get('service') or '')
    action = str(claims.get('action') or '')
    arguments_hash = str(claims.get('arguments_hash') or '')
    if not agent_id or company_id is None or not service or not action or not arguments_hash:
        return None
    return {
        'agent_id': agent_id,
        'company_id': int(company_id),
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
    }


def public_approval_status(row: McpApprovalRequest, *, now) -> str:
    if row.status == McpApprovalRequest.STATUS_REJECTED:
        return 'denied'
    if row.status == McpApprovalRequest.STATUS_EXECUTED:
        return 'expired'
    if row.status == McpApprovalRequest.STATUS_EXPIRED or row.expires_at <= now:
        return 'expired'
    if row.status == McpApprovalRequest.STATUS_APPROVED:
        return 'approved'
    if row.status == McpApprovalRequest.STATUS_PENDING:
        return 'pending'
    return 'expired'


def lookup_approval_row(binding: dict[str, Any]) -> McpApprovalRequest | None:
    return (
        McpApprovalRequest.objects.filter(
            agent_id=binding['agent_id'],
            company_id=binding['company_id'],
            service=binding['service'],
            action=binding['action'],
            arguments_hash=binding['arguments_hash'],
        )
        .order_by('-created_at')
        .first()
    )


def get_bound_approval(approval_id: str, binding: dict[str, Any]) -> McpApprovalRequest | None:
    try:
        return McpApprovalRequest.objects.get(
            pk=approval_id,
            agent_id=binding['agent_id'],
            company_id=binding['company_id'],
            service=binding['service'],
            arguments_hash=binding['arguments_hash'],
        )
    except McpApprovalRequest.DoesNotExist:
        return None
