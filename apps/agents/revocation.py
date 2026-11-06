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


def blocked_agent_snapshots(*, company_id: int | None = None) -> list[dict]:
    """Blocked agents with fields services use to cross-check tenant binding."""
    ids = blocked_agent_ids(company_id=company_id)
    if not ids:
        return []
    qs = Agent.objects.filter(pk__in=ids).order_by('id')
    rows: list[dict] = []
    for agent in qs:
        gc = getattr(agent, 'global_company_id', None)
        cb = getattr(agent, 'company_binding_version', None)
        snap: dict = {
            'agent_id': str(agent.id),
            'company_id': agent.company_id,
            'is_active': agent.is_active,
            'paused': agent.paused_at is not None,
            'grant_version': int(getattr(agent, 'grant_version', 0) or 0),
        }
        if gc is not None:
            snap['global_company_id'] = str(gc)
        if cb is not None:
            snap['company_binding_version'] = int(cb)
        rows.append(snap)
    return rows
