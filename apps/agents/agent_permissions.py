"""Invalidate session Allow grants when company-scoped MCP permissions change."""

from __future__ import annotations

from django.db.models import F

from apps.agents.approval_session import revoke_session_grants_for_agent
from apps.agents.models import Agent


def bump_agent_permission_version(agent: Agent) -> None:
    Agent.objects.filter(pk=agent.pk).update(permission_version=F('permission_version') + 1)


def invalidate_agent_session_grants(agent: Agent) -> None:
    revoke_session_grants_for_agent(agent)
    bump_agent_permission_version(agent)


def invalidate_agents_for_user_company(*, user_id: int, company_id: int) -> None:
    """When membership ends or is disabled, drop session grants for that user's agents."""
    for agent in Agent.objects.filter(company_id=company_id, created_by_id=user_id):
        invalidate_agent_session_grants(agent)
