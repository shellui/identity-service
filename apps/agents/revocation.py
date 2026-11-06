"""Revocation list for downstream MCP services (30 s cache recommended)."""

from __future__ import annotations

from django.db.models import Max
from django.utils import timezone

from apps.agents.models import Agent

REVOCATION_CACHE_SECONDS = 30


def active_max_grant_version(*, company_id: int | None = None) -> int:
    """Largest Agent.grant_version for non-revoked agents; drives policy fingerprint for active tenants."""
    qs = Agent.objects.filter(revoked_at__isnull=True)
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    val = qs.aggregate(m=Max('grant_version')).get('m')
    return int(val or 0)


def revoked_agent_ids(*, company_id: int | None = None) -> list[str]:
    qs = Agent.objects.filter(revoked_at__isnull=False)
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    return [str(aid) for aid in qs.values_list('id', flat=True)]


def paused_agent_ids(*, company_id: int | None = None) -> list[str]:
    qs = Agent.objects.filter(paused_at__isnull=False, revoked_at__isnull=True)
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    return [str(aid) for aid in qs.values_list('id', flat=True)]


def expired_agent_ids(*, company_id: int | None = None) -> list[str]:
    now = timezone.now()
    qs = Agent.objects.filter(expires_at__isnull=False, expires_at__lte=now, revoked_at__isnull=True)
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    return [str(aid) for aid in qs.values_list('id', flat=True)]


def blocked_agent_ids(*, company_id: int | None = None) -> list[str]:
    ids = set(revoked_agent_ids(company_id=company_id))
    ids.update(paused_agent_ids(company_id=company_id))
    ids.update(expired_agent_ids(company_id=company_id))
    return sorted(ids)


def agent_snapshot(agent: Agent) -> dict:
    """One regional agent row. ``agent_id`` is the regional primary key, never a global agent id."""
    snap: dict = {
        'agent_id': str(agent.id),
        'company_id': int(agent.company_id),
        'is_active': bool(agent.is_active),
        'paused': agent.paused_at is not None,
        'grant_version': int(getattr(agent, 'grant_version', 0) or 0),
    }
    gc = getattr(agent, 'global_company_id', None)
    cb = getattr(agent, 'company_binding_version', None)
    if gc is not None:
        snap['global_company_id'] = str(gc)
    if cb is not None:
        snap['company_binding_version'] = int(cb)
    return snap


def regional_agent_snapshots(*, company_id: int | None = None) -> list[dict]:
    """Every regional agent for this poll, including active rows consumers authorize against."""
    qs = Agent.objects.all().order_by('id')
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    return [agent_snapshot(agent) for agent in qs]


def blocked_agent_snapshots(*, company_id: int | None = None) -> list[dict]:
    """Blocked subset only. The poll response uses ``regional_agent_snapshots``."""
    ids = blocked_agent_ids(company_id=company_id)
    if not ids:
        return []
    qs = Agent.objects.filter(pk__in=ids).order_by('id')
    return [agent_snapshot(agent) for agent in qs]
