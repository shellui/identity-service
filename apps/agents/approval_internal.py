"""Shared MCP approval lookup and consume binding (internal API + Identity /mcp)."""

from __future__ import annotations

from typing import Any

from django.utils import timezone

from apps.agents.approval_global import ensure_global_approval_claims, is_global_placeholder_company_id
from apps.agents.models import McpApprovalRequest


def approval_binding_from_claims(claims: dict[str, Any]) -> dict[str, Any] | None:
    agent_id = str(claims.get('agent_id') or '')
    company_id = claims.get('company_id')
    service = str(claims.get('service') or '')
    action = str(claims.get('action') or '')
    arguments_hash = str(claims.get('arguments_hash') or '')
    if not agent_id or company_id is None or not service or not action or not arguments_hash:
        return None
    try:
        cid = int(company_id)
    except (TypeError, ValueError):
        return None

    if is_global_placeholder_company_id(cid):
        meta = ensure_global_approval_claims(claims)
        if meta is None:
            return None
        return {
            'agent_id': agent_id,
            'company_id': cid,
            'service': service,
            'action': action,
            'arguments_hash': arguments_hash,
            'is_global': True,
            'global_meta': meta,
        }

    return {
        'agent_id': agent_id,
        'company_id': cid,
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
        'is_global': False,
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
    q = approval_lookup_filter(binding)
    return McpApprovalRequest.objects.filter(**q).order_by('-created_at').first()


def approval_lookup_filter(binding: dict[str, Any]) -> dict:
    base = {
        'agent_id': binding['agent_id'],
        'service': binding['service'],
        'action': binding['action'],
        'arguments_hash': binding['arguments_hash'],
    }
    if binding.get('is_global'):
        meta = binding.get('global_meta') or {}
        return {
            **base,
            'company_id__isnull': True,
            'global_agent_id': meta.get('global_agent_id'),
            'global_company_id': meta.get('global_company_id'),
            'company_binding_version': meta.get('company_binding_version'),
        }
    return {**base, 'company_id': binding['company_id']}


def get_bound_approval(approval_id: str, binding: dict[str, Any]) -> McpApprovalRequest | None:
    try:
        flt = {'pk': approval_id, **approval_lookup_filter(binding)}
        return McpApprovalRequest.objects.get(**flt)
    except McpApprovalRequest.DoesNotExist:
        return None
