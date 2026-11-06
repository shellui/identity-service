"""Propagate global agent revocation to regional MCP agent rows."""

from __future__ import annotations

import uuid

from django.utils import timezone

from apps.agents.agent_permissions import invalidate_agent_session_grants
from apps.agents.models import Agent, GlobalAgentRevocation
from apps.agents.tokens import revoke_all_agent_refresh_sessions


def revoke_regional_agents_for_global(global_agent_id: uuid.UUID) -> int:
    """Revoke every regional agent linked to this global agent id. Returns rows updated."""
    GlobalAgentRevocation.objects.get_or_create(global_agent_id=global_agent_id)
    now = timezone.now()
    agents = list(Agent.objects.filter(global_agent_id=global_agent_id, revoked_at__isnull=True))
    if not agents:
        return 0
    Agent.objects.filter(pk__in=[a.pk for a in agents]).update(revoked_at=now)
    for agent in agents:
        revoke_all_agent_refresh_sessions(agent)
        invalidate_agent_session_grants(agent)
    return len(agents)


def global_agent_exchange_blocked(global_agent_id: uuid.UUID) -> bool:
    if GlobalAgentRevocation.objects.filter(global_agent_id=global_agent_id).exists():
        return True
    return Agent.objects.filter(global_agent_id=global_agent_id, revoked_at__isnull=False).exists()
