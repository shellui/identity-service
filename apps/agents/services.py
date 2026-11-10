"""MCP service discovery URLs."""

from __future__ import annotations

from django.conf import settings


def _origin(url: str) -> str:
    return str(url or '').strip().rstrip('/')


def list_mcp_services(*, company_id: int | None = None) -> list[dict[str, str]]:
    """Return MCP base URLs for connected Shellui services.

    ``company_id`` selects the per-company AI gateway URL (``{AI_SERVICE_URL}/c/<id>/mcp``).
    Callers that resolve plain ``{origin}/mcp`` resources omit it.
    """
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
    saas = _origin(getattr(settings, 'SAAS_SERVICE_URL', ''))
    if saas:
        items.append({'id': 'saas', 'name': 'SaaS', 'mcp_url': f'{saas}/mcp'})
    ai = _origin(getattr(settings, 'AI_SERVICE_URL', ''))
    if ai:
        if company_id is not None:
            mcp_url = f'{ai}/c/{int(company_id)}/mcp'
        else:
            mcp_url = f'{ai}/mcp'
        items.append({'id': 'ai', 'name': 'AI', 'mcp_url': mcp_url})
    return items


def service_allowed(agent_services: list[str], service_id: str) -> bool:
    allowed = {str(s) for s in (agent_services or [])}
    return service_id in allowed
