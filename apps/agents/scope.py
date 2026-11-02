"""Compare and narrow MCP agent scopes (access mode, read level, services, destructive)."""

from __future__ import annotations

from apps.agents.models import Agent

_ACCESS_RANK = {
    Agent.ACCESS_READ_ONLY: 0,
    Agent.ACCESS_ASK: 1,
    Agent.ACCESS_FULL: 2,
}
_READ_RANK = {
    Agent.READ_SAFE: 0,
    Agent.READ_SENSITIVE: 1,
}
_ALLOWED_SERVICES = {choice[0] for choice in Agent.SERVICE_CHOICES}


def parse_services(scope: str | None) -> list[str]:
    return [part for part in str(scope or '').split() if part in _ALLOWED_SERVICES]


def access_within(global_mode: str, requested: str | None) -> str | None:
    if global_mode not in _ACCESS_RANK:
        return None
    chosen = requested or global_mode
    if chosen not in _ACCESS_RANK:
        return None
    if _ACCESS_RANK[chosen] > _ACCESS_RANK[global_mode]:
        return None
    return chosen


def read_within(global_level: str, requested: str | None) -> str | None:
    if global_level not in _READ_RANK:
        return None
    chosen = requested or global_level
    if chosen not in _READ_RANK:
        return None
    if _READ_RANK[chosen] > _READ_RANK[global_level]:
        return None
    return chosen


def destructive_within(*, global_allowed: bool, requested: bool | None) -> bool:
    if requested is None:
        return bool(global_allowed)
    if requested and not global_allowed:
        return False
    return bool(requested)


def services_within(global_services: list[str], requested: list[str] | None) -> list[str] | None:
    allowed = [s for s in global_services if s in _ALLOWED_SERVICES]
    if not allowed:
        return None
    if not requested:
        return allowed
    narrowed = [s for s in requested if s in _ALLOWED_SERVICES]
    if not narrowed:
        return None
    if any(s not in set(allowed) for s in narrowed):
        return None
    return narrowed
