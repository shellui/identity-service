"""Short-lived session write grants after "Allow for this session" (client path only)."""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from apps.agents.models import Agent, McpApprovalSessionGrant


def session_ttl_seconds() -> int:
    raw = int(getattr(settings, 'MCP_APPROVAL_SESSION_TTL_SECONDS', 60) or 60)
    return max(30, min(raw, 60))


def grant_session_write(
    *,
    agent: Agent,
    connection_id: str = '',
    granted_by_id: int | None = None,
    ttl_seconds: int | None = None,
) -> McpApprovalSessionGrant:
    now = timezone.now()
    ttl = int(ttl_seconds) if ttl_seconds is not None else session_ttl_seconds()
    conn = (connection_id or '').strip()[:128]
    McpApprovalSessionGrant.objects.filter(
        agent=agent,
        connection_id=conn,
        revoked_at__isnull=True,
        expires_at__gt=now,
    ).update(revoked_at=now)
    return McpApprovalSessionGrant.objects.create(
        agent=agent,
        company_id=agent.company_id,
        connection_id=conn,
        granted_by_id=granted_by_id,
        expires_at=now + timedelta(seconds=ttl),
    )


def revoke_session_grants_for_agent(agent: Agent) -> None:
    now = timezone.now()
    McpApprovalSessionGrant.objects.filter(agent=agent, revoked_at__isnull=True).update(revoked_at=now)


def revoke_session_grant(*, agent_id: str, company_id: int, connection_id: str = '') -> int:
    now = timezone.now()
    conn = (connection_id or '').strip()[:128]
    return McpApprovalSessionGrant.objects.filter(
        agent_id=agent_id,
        company_id=company_id,
        connection_id=conn,
        revoked_at__isnull=True,
        expires_at__gt=now,
    ).update(revoked_at=now)


def active_session_grant(
    *,
    agent_id: str,
    company_id: int,
    connection_id: str = '',
) -> McpApprovalSessionGrant | None:
    now = timezone.now()
    conn = (connection_id or '').strip()[:128]
    return (
        McpApprovalSessionGrant.objects.filter(
            agent_id=agent_id,
            company_id=company_id,
            connection_id=conn,
            revoked_at__isnull=True,
            expires_at__gt=now,
        )
        .order_by('-expires_at')
        .first()
    )


def session_allows_non_destructive_write(
    *,
    agent_id: str,
    company_id: int,
    connection_id: str = '',
    is_destructive: bool,
) -> bool:
    if is_destructive:
        return False
    return active_session_grant(agent_id=agent_id, company_id=company_id, connection_id=connection_id) is not None
