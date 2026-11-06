"""Strict validation for internal MCP call log ingest (no untrusted argument bodies)."""

from __future__ import annotations

import re
from urllib.parse import unquote

from django.conf import settings

from apps.agents.mcp_resources import catalog_resources_by_url

# Downstream services expose JSON-RPC at POST /mcp only.
_ALLOWED_HTTP_METHODS = frozenset({'POST'})
_TOOL_NAME = re.compile(r'^[a-zA-Z][a-zA-Z0-9_.-]{0,254}$')


def canonical_call_path(method: str, path: str) -> str | None:
    """Return ``METHOD /mcp`` when path is exactly the service MCP route, else None."""
    m = (method or '').strip().upper()[:10]
    if m not in _ALLOWED_HTTP_METHODS:
        return None
    raw = (path or '').strip()
    raw = raw.split('?', 1)[0].split('#', 1)[0]
    raw = unquote(raw).strip()
    if raw == '':
        raw = '/mcp'
    if raw != '/mcp':
        return None
    return f'{m} /mcp'


def safe_operation_title(tool: str) -> str:
    t = (tool or '').strip()
    if t and _TOOL_NAME.match(t):
        return t[:255]
    return 'MCP tool call'


def fixed_resource_label_for_service(*, service_id: str, method: str, path: str) -> str | None:
    pair = canonical_call_path(method, path)
    if pair is None:
        return None
    catalog = catalog_resources_by_url()
    for url, sid in catalog.items():
        if sid != service_id:
            continue
        from apps.agents.mcp_resources import normalize_mcp_resource

        origin = normalize_mcp_resource(url)
        if not origin:
            continue
        try:
            from urllib.parse import urlsplit

            host = (urlsplit(origin).hostname or '').lower()
        except ValueError:
            continue
        ai = (getattr(settings, 'AI_SERVICE_URL', '') or '').strip()
        if ai and host == (urlsplit(ai.rstrip('/')).hostname or '').lower():
            continue
        return f'{pair} ({service_id})'
    return None
