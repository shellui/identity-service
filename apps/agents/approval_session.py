"""Short-lived session write grants after "Allow for this session" (client path only)."""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from apps.agents.models import Agent, McpApprovalRequest, McpApprovalSessionGrant


def session_ttl_seconds() -> int:
    raw = int(getattr(settings, 'MCP_APPROVAL_SESSION_TTL_SECONDS', 60) or 60)
    return max(30, min(raw, 60))


def grant_session_write(
    *,
    agent: Agent,
    connection_id: str = '',
    granted_by_id: int | None = None,
    ttl_seconds: int | None = None,
    service: str = '',
    action: str = '',
    arguments_hash: str = '',
    approval_request: McpApprovalRequest | None = None,
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
    snap = Agent.objects.only(
        'grant_version',
        'global_company_id',
        'company_binding_version',
        'company_id',
        'services_allowed',
        'setup_company_id',
        'setup_context_expires_at',
        'setup_new_company_grant',
        'setup_mcp_session_ttl_seconds',
    ).get(pk=agent.pk)
    return McpApprovalSessionGrant.objects.create(
        agent=agent,
        company_id=agent.company_id,
        approval_request=approval_request,
        service=str(service or '')[:32],
        action=str(action or '')[:255],
        arguments_hash=str(arguments_hash or '')[:64],
        connection_id=conn,
        granted_by_id=granted_by_id,
        expires_at=now + timedelta(seconds=ttl),
        agent_grant_version=int(snap.grant_version or 0),
        global_company_id=snap.global_company_id,
        company_binding_version=snap.company_binding_version,
        services_allowed=list(snap.services_allowed or []),
        setup_company_id=getattr(snap, 'setup_company_id', None),
        setup_context_expires_at=getattr(snap, 'setup_context_expires_at', None),
        setup_new_company_grant=bool(getattr(snap, 'setup_new_company_grant', False)),
        setup_mcp_session_ttl_seconds=getattr(snap, 'setup_mcp_session_ttl_seconds', None),
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


def _session_grant_matches_live_agent(grant: McpApprovalSessionGrant, agent: Agent) -> bool:
    """True when the grant row snapshot still matches current agent authority (least privilege)."""
    if int(getattr(grant, 'agent_grant_version', 0) or 0) != int(getattr(agent, 'grant_version', 0) or 0):
        return False
    ag_gc = getattr(agent, 'global_company_id', None)
    g_gc = getattr(grant, 'global_company_id', None)
    ag_cb = getattr(agent, 'company_binding_version', None)
    g_cb = getattr(grant, 'company_binding_version', None)
    if ag_gc is None:
        if g_gc is not None or g_cb is not None:
            return False
    else:
        if g_gc is None or g_cb is None:
            return False
        if g_gc != ag_gc:
            return False
        if int(g_cb) != int(ag_cb or 0):
            return False
    gsv = list(grant.services_allowed or [])
    if gsv and not set(gsv) <= set(agent.services_allowed or []):
        return False
    return True


def active_session_grant(
    *,
    agent_id: str,
    company_id: int,
    connection_id: str = '',
    service: str = '',
    action: str = '',
    arguments_hash: str = '',
) -> McpApprovalSessionGrant | None:
    now = timezone.now()
    conn = (connection_id or '').strip()[:128]
    svc = (service or '').strip()[:32]
    act = (action or '').strip()[:255]
    ah = (arguments_hash or '').strip()[:64]
    qs = (
        McpApprovalSessionGrant.objects.filter(
            agent_id=agent_id,
            company_id=company_id,
            connection_id=conn,
            revoked_at__isnull=True,
            expires_at__gt=now,
        )
        .select_related('agent', 'approval_request')
        .filter(agent__revoked_at__isnull=True, agent__paused_at__isnull=True)
        .order_by('-expires_at')
    )

    def _grant_fingerprint(grant: McpApprovalSessionGrant) -> tuple[str, str, str]:
        if (grant.arguments_hash or '').strip():
            return (grant.service or '')[:32], (grant.action or '')[:255], (grant.arguments_hash or '')[:64]
        ar = getattr(grant, 'approval_request', None)
        if ar is not None:
            return (ar.service or '')[:32], (ar.action or '')[:255], (ar.arguments_hash or '')[:64]
        return '', '', ''

    for grant in qs:
        agent = grant.agent
        if not _session_grant_matches_live_agent(grant, agent):
            continue
        if svc and act and ah:
            gs, ga, gh = _grant_fingerprint(grant)
            if gh and (gs != svc or ga != act or gh != ah):
                continue
            if not gh:
                continue
        return grant
    return None


def session_allows_non_destructive_write(
    *,
    agent_id: str,
    company_id: int,
    connection_id: str = '',
    is_destructive: bool,
    service: str = '',
    action: str = '',
    arguments_hash: str = '',
) -> bool:
    if is_destructive:
        return False
    return (
        active_session_grant(
            agent_id=agent_id,
            company_id=company_id,
            connection_id=connection_id,
            service=service,
            action=action,
            arguments_hash=arguments_hash,
        )
        is not None
    )
