"""MCP service discovery URLs."""

from __future__ import annotations

from django.conf import settings


def _origin(url: str) -> str:
    return str(url or '').strip().rstrip('/')


def list_mcp_services() -> list[dict[str, str]]:
    """Return MCP base URLs for connected Shellui services."""
    identity = _origin(getattr(settings, 'JWT_ISSUER', '') or '')
    items: list[dict[str, str]] = []
    if identity:
        items.append({'id': 'identity', 'name': 'Identity', 'mcp_url': f'{identity}/mcp'})
    storage = _origin(getattr(settings, 'STORAGE_SERVICE_URL', ''))
    if storage:
        items.append({'id': 'storage', 'name': 'Storage', 'mcp_url': f'{storage}/mcp'})
    hosting = _origin(getattr(settings, 'HOSTING_SERVICE_URL', ''))
    if hosting:
        items.append({'id': 'hosting', 'name': 'Hosting', 'mcp_url': f'{hosting}/mcp'})
    email = _origin(getattr(settings, 'EMAIL_SERVICE_URL', ''))
    if email and getattr(settings, 'EMAIL_SERVICE_API_KEY', ''):
        items.append({'id': 'email', 'name': 'Email', 'mcp_url': f'{email}/mcp'})
    return items


def service_allowed(agent_services: list[str], service_id: str) -> bool:
    allowed = {str(s) for s in (agent_services or [])}
    return service_id in allowed
