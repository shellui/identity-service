"""Identity-side MCP resource catalog (from existing service URL settings)."""

from __future__ import annotations

from django.conf import settings

from apps.agents.services import list_mcp_services
from shellui_mcp.resources import mcp_resource_from_origin, normalize_resource_indicator


def catalog_resources_by_url() -> dict[str, str]:
    """Map canonical resource URL to service id (identity, storage, …)."""
    out: dict[str, str] = {}
    for item in list_mcp_services():
        url = normalize_resource_indicator(item.get('mcp_url') or '')
        if url:
            out[url] = str(item['id'])
    issuer = mcp_resource_from_origin(getattr(settings, 'JWT_ISSUER', '') or '')
    if issuer:
        normalized = normalize_resource_indicator(issuer)
        if normalized:
            out.setdefault(normalized, 'identity')
    return out


def resolve_mcp_resource(raw: str | None) -> tuple[str, str] | tuple[None, str]:
    """Return (resource_url, service_id) or (None, error_code)."""
    url = normalize_resource_indicator(raw)
    if not url:
        return None, 'invalid_resource'
    service_id = catalog_resources_by_url().get(url)
    if not service_id:
        return None, 'unknown_resource'
    return url, service_id
