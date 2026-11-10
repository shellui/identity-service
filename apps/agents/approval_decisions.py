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
from apps.agents.mcp_setup_session_ttl import resolve_session_grant_ttl_seconds
from apps.agents.approval_session import grant_session_write
from apps.agents.models import McpApprovalRequest


class ConsentFieldError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def parse_decision_consent(body: dict) -> tuple[str, str]:
    """Optional ``consent`` and ``client_name`` on an internal decide call.

    Returns ``(consent, client_name)``. Either string is empty when the caller omitted it.
    """
    consent = ''
    if 'consent' in body:
        raw = body.get('consent')
        allowed = {McpApprovalRequest.CONSENT_IN_CHAT, McpApprovalRequest.CONSENT_LINK}
        if not isinstance(raw, str) or raw not in allowed:
            raise ConsentFieldError('consent must be in_chat or link.')
        consent = raw
    client_name = ''
    if 'client_name' in body:
        raw_name = body.get('client_name')
        if not isinstance(raw_name, str):
            raise ConsentFieldError('client_name must be a string.')
        text = ''.join(ch if ord(ch) >= 32 else ' ' for ch in raw_name)
        text = ' '.join(text.split())
        if len(text) > McpApprovalRequest.CLIENT_NAME_MAX:
            raise ConsentFieldError('client_name must be at most 80 characters.')
        client_name = text
    return consent, client_name


class ApprovalDecisionError(Exception):
    def __init__(self, message: str, *, status: int = 409):
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass(frozen=True)
class ApprovalDecisionResult:
    row: McpApprovalRequest
    audit_status: str


def lock_approval_for_update(**lookup) -> McpApprovalRequest:
    """Lock this approval row inside the current transaction.

    ``agent`` is nullable, so ``select_for_update().select_related('agent')`` becomes
    ``FOR UPDATE`` on the outer join. PostgreSQL rejects that. ``of=('self',)`` locks
    only the approval row and still loads ``agent`` for the owner check and audit.
    """
    return (
        McpApprovalRequest.objects.select_for_update(of=('self',))
        .select_related('agent')
        .get(**lookup)
    )


def _ensure_pending(row: McpApprovalRequest) -> None:
    now = timezone.now()
    if row.status != McpApprovalRequest.STATUS_PENDING:
        raise ApprovalDecisionError('Approval is not pending.')
    if row.expires_at <= now:
        raise ApprovalDecisionError('Approval is not pending.', status=409)


def _reject_in_chat_destructive(row: McpApprovalRequest, consent: str) -> None:
    if consent == McpApprovalRequest.CONSENT_IN_CHAT and row.is_destructive:
        raise ApprovalDecisionError('In-chat consent is not allowed for a destructive tool.', status=409)


def _store_consent(row: McpApprovalRequest, *, consent: str, client_name: str) -> list[str]:
    fields: list[str] = []
    if consent:
        row.consent = consent
        fields.append('consent')
    if client_name:
        row.client_name = client_name
        fields.append('client_name')
    return fields


@transaction.atomic
def approve_pending(
    row: McpApprovalRequest,
    *,
    decided_by,
    audit_status: str,
    actor_email: str | None = None,
    consent: str = '',
    client_name: str = '',
) -> ApprovalDecisionResult:
    row = lock_approval_for_update(pk=row.pk)
    _ensure_pending(row)
    _reject_in_chat_destructive(row, consent)
    row.status = McpApprovalRequest.STATUS_APPROVED
    row.decided_at = timezone.now()
    row.decided_by = decided_by
    row.save(update_fields=['status', 'decided_at', 'decided_by', *_store_consent(row, consent=consent, client_name=client_name)])
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
    consent: str = '',
    client_name: str = '',
) -> ApprovalDecisionResult:
    row = lock_approval_for_update(pk=row.pk)
    _ensure_pending(row)
    _reject_in_chat_destructive(row, consent)
    row.status = McpApprovalRequest.STATUS_REJECTED
    row.decided_at = timezone.now()
    row.decided_by = decided_by
    row.save(update_fields=['status', 'decided_at', 'decided_by', *_store_consent(row, consent=consent, client_name=client_name)])
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
    consent: str = '',
    client_name: str = '',
) -> ApprovalDecisionResult:
    return approve_pending(
        row,
        decided_by=None,
        audit_status=APPROVAL_AUDIT_CLIENT_ALLOWED,
        actor_email=actor_email,
        consent=consent,
        client_name=client_name,
    )


def client_deny(
    row: McpApprovalRequest,
    *,
    actor_email: str | None,
    consent: str = '',
    client_name: str = '',
) -> ApprovalDecisionResult:
    return deny_pending(
        row,
        decided_by=None,
        audit_status=APPROVAL_AUDIT_CLIENT_DENIED,
        actor_email=actor_email,
        consent=consent,
        client_name=client_name,
    )


def client_allow_session(
    row: McpApprovalRequest,
    *,
    connection_id: str = '',
    actor_email: str | None,
    caller_name: str = '',
    assertion_claims: dict | None = None,
    consent: str = '',
    client_name: str = '',
) -> ApprovalDecisionResult:
    if row.is_destructive:
        raise ApprovalDecisionError('Destructive actions cannot use session allow.', status=409)
    ttl_seconds = resolve_session_grant_ttl_seconds(
        caller_name=caller_name,
        assertion_claims=assertion_claims,
        agent=row.agent,
    )
    with transaction.atomic():
        row_locked = lock_approval_for_update(pk=row.pk)
        _ensure_pending(row_locked)
        _reject_in_chat_destructive(row_locked, consent)
        if row_locked.is_destructive:
            raise ApprovalDecisionError('Destructive actions cannot use session allow.', status=409)
        row_locked.status = McpApprovalRequest.STATUS_APPROVED
        row_locked.decided_at = timezone.now()
        row_locked.decided_by = None
        row_locked.save(
            update_fields=[
                'status',
                'decided_at',
                'decided_by',
                *_store_consent(row_locked, consent=consent, client_name=client_name),
            ]
        )
        record_approval_decision_event(
            row_locked,
            status=APPROVAL_AUDIT_CLIENT_SESSION_ALLOWED,
            actor_email=actor_email,
            user=None,
        )
        grant_session_write(
            agent=row_locked.agent,
            connection_id=connection_id,
            ttl_seconds=ttl_seconds,
            approval_request=row_locked,
            service=str(row_locked.service or '')[:32],
            action=str(row_locked.action or '')[:255],
            arguments_hash=str(row_locked.arguments_hash or '')[:64],
        )
    row_locked.refresh_from_db()
    return ApprovalDecisionResult(row=row_locked, audit_status=APPROVAL_AUDIT_CLIENT_SESSION_ALLOWED)
