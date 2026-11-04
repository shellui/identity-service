"""Identity-side MCP resource catalog (from existing service URL settings).

Downstream services keep their plain ``{origin}/mcp`` resource. The ai-service gateway is
reached per company: ``{AI_SERVICE_URL}/c/<company_id>/mcp``. Agents that a user connects
through OAuth always use the per-company gateway resource, so the company comes from the
URL and never from a default.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from django.conf import settings

from apps.agents.services import list_mcp_services
from shellui_django.mcp.resources import mcp_resource_from_origin, normalize_resource_indicator

_COMPANY_PATH = re.compile(r'^/c/([1-9][0-9]{0,18})/mcp$')
_LOOPBACK_HOSTS = ('127.0.0.1', 'localhost', '::1')
GATEWAY_SERVICE_ID = 'ai'


def _normalize_company_resource(raw: str | None) -> str | None:
    s = str(raw or '').strip()
    if not s or '#' in s or '?' in s:
        return None
    s = s.rstrip('/')
    try:
        parsed = urlsplit(s)
    except ValueError:
        return None
    if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username or parsed.password:
        return None
    if not _COMPANY_PATH.match(parsed.path):
        return None
    if parsed.scheme == 'http' and (parsed.hostname or '').lower() not in _LOOPBACK_HOSTS:
        return None
    return s


def normalize_mcp_resource(raw: str | None) -> str | None:
    """Canonical ``{origin}/mcp`` or ``{origin}/c/<company_id>/mcp``. None for anything else."""
    return normalize_resource_indicator(raw) or _normalize_company_resource(raw)


def resource_company_id(resource: str | None) -> int | None:
    """Company id carried by a per-company resource, else None."""
    url = _normalize_company_resource(resource)
    if not url:
        return None
    match = _COMPANY_PATH.match(urlsplit(url).path)
    return int(match.group(1)) if match else None


def _gateway_origin() -> str:
    return str(getattr(settings, 'AI_SERVICE_URL', '') or '').strip().rstrip('/')


def gateway_resource_for_company(company_id: int) -> str:
    origin = _gateway_origin()
    if not origin:
        return ''
    return _normalize_company_resource(f'{origin}/c/{int(company_id)}/mcp') or ''


def catalog_resources_by_url() -> dict[str, str]:
    """Map canonical plain resource URL to service id (identity, storage, …)."""
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
    """Return (resource_url, service_id) or (None, error_code).

    Accepts every plain catalog resource and the per-company gateway resource on the
    configured ai-service origin.
    """
    company_url = _normalize_company_resource(raw)
    if company_url:
        origin = _gateway_origin()
        company_id = resource_company_id(company_url)
        if origin and company_id is not None and company_url == gateway_resource_for_company(company_id):
            return company_url, GATEWAY_SERVICE_ID
        return None, 'unknown_resource'
    url = normalize_resource_indicator(raw)
    if not url:
        return None, 'invalid_resource'
    service_id = catalog_resources_by_url().get(url)
    if not service_id:
        return None, 'unknown_resource'
    return url, service_id
