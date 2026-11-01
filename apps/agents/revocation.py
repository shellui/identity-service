"""Revocation list for downstream MCP services (30 s cache recommended)."""

from __future__ import annotations

from django.utils import timezone

from apps.agents.models import Agent

REVOCATION_CACHE_SECONDS = 30


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
