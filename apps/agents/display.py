"""Display helpers for MCP agent admin APIs."""

from __future__ import annotations

from apps.agents.models import Agent

_GLOBAL_AGENT_CREATOR_LABEL = 'Global MCP agent'


def agent_created_by(agent: Agent) -> dict | None:
    """
    Stable creator label for admin agent list/detail JSON.

    Returns ``None`` when the creator user was never recorded or was removed.
    """
    user = agent.created_by
    if user is not None:
        display_name = user.get_full_name() or user.email or user.get_username()
        return {'id': user.pk, 'display_name': display_name}
    if agent.global_agent_id is not None:
        return {'id': None, 'display_name': _GLOBAL_AGENT_CREATOR_LABEL}
    return None
