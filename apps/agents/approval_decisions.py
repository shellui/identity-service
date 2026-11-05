"""Shared approve and deny logic for Settings, fallback, and internal client APIs."""

from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from apps.agents.approval_audit import (
    APPROVAL_AUDIT_APPROVED,
    APPROVAL_AUDIT_CLIENT_ALLOWED,
    APPROVAL_AUDIT_CLIENT_DENIED,
    APPROVAL_AUDIT_CLIENT_SESSION_ALLOWED,
    APPROVAL_AUDIT_DENIED,
    record_approval_decision_event,
)
from apps.agents.approval_session import grant_session_write
from apps.agents.models import McpApprovalRequest


class ApprovalDecisionError(Exception):
    def __init__(self, message: str, *, status: int = 409):
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass(frozen=True)
class ApprovalDecisionResult:
    row: McpApprovalRequest
    audit_status: str


def _ensure_pending(row: McpApprovalRequest) -> None:
    now = timezone.now()
    if row.status != McpApprovalRequest.STATUS_PENDING:
        raise ApprovalDecisionError('Approval is not pending.')
    if row.expires_at <= now:
        raise ApprovalDecisionError('Approval is not pending.', status=409)


@transaction.atomic
def approve_pending(
    row: McpApprovalRequest,
    *,
    decided_by,
    audit_status: str,
    actor_email: str | None = None,
) -> ApprovalDecisionResult:
    row = McpApprovalRequest.objects.select_for_update().select_related('agent').get(pk=row.pk)
    _ensure_pending(row)
    row.status = McpApprovalRequest.STATUS_APPROVED
    row.decided_at = timezone.now()
    row.decided_by = decided_by
    row.save(update_fields=['status', 'decided_at', 'decided_by'])
    record_approval_decision_event(
        row,
        status=audit_status,
        actor_email=actor_email or getattr(decided_by, 'email', None),
        user=decided_by,
    )
    return ApprovalDecisionResult(row=row, audit_status=audit_status)


@transaction.atomic
def deny_pending(
    row: McpApprovalRequest,
    *,
    decided_by,
    audit_status: str,
    actor_email: str | None = None,
) -> ApprovalDecisionResult:
    row = McpApprovalRequest.objects.select_for_update().select_related('agent').get(pk=row.pk)
    _ensure_pending(row)
    row.status = McpApprovalRequest.STATUS_REJECTED
    row.decided_at = timezone.now()
    row.decided_by = decided_by
    row.save(update_fields=['status', 'decided_at', 'decided_by'])
    record_approval_decision_event(
        row,
        status=audit_status,
        actor_email=actor_email or getattr(decided_by, 'email', None),
        user=decided_by,
    )
    return ApprovalDecisionResult(row=row, audit_status=audit_status)


def settings_approve(row: McpApprovalRequest, *, user) -> ApprovalDecisionResult:
    return approve_pending(row, decided_by=user, audit_status=APPROVAL_AUDIT_APPROVED)


def settings_deny(row: McpApprovalRequest, *, user) -> ApprovalDecisionResult:
    return deny_pending(row, decided_by=user, audit_status=APPROVAL_AUDIT_DENIED)


def client_allow(
    row: McpApprovalRequest,
    *,
    actor_email: str | None,
) -> ApprovalDecisionResult:
    return approve_pending(
        row,
        decided_by=None,
        audit_status=APPROVAL_AUDIT_CLIENT_ALLOWED,
        actor_email=actor_email,
    )


def client_deny(
    row: McpApprovalRequest,
    *,
    actor_email: str | None,
) -> ApprovalDecisionResult:
    return deny_pending(
        row,
        decided_by=None,
        audit_status=APPROVAL_AUDIT_CLIENT_DENIED,
        actor_email=actor_email,
    )


def client_allow_session(
    row: McpApprovalRequest,
    *,
    connection_id: str = '',
    actor_email: str | None,
) -> ApprovalDecisionResult:
    if row.is_destructive:
        raise ApprovalDecisionError('Destructive actions cannot use session allow.', status=409)
    grant_session_write(agent=row.agent, connection_id=connection_id)
    return approve_pending(
        row,
        decided_by=None,
        audit_status=APPROVAL_AUDIT_CLIENT_SESSION_ALLOWED,
        actor_email=actor_email,
    )
