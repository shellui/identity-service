"""OpenAPI copy for company-owner admin APIs (written for agents and humans)."""

from __future__ import annotations

from drf_spectacular.utils import OpenApiResponse

from apps.authapi.mcp_openapi import MCP_EXPLICIT_REGISTRY, MCP_REQUIRED_OPERATION_IDS
from apps.authapi.openapi_mcp_registry import MCP_SPECS
from apps.authapi.schema import ErrorSerializer

PERMISSIONS_BLOCK = (
    'Permissions: Shellui company owner for the company in the JWT (`company_id`), or Shellui staff. '
    'Send `Authorization: Bearer <jwt>` from identity-service. MCP agent tokens and service keys '
    'cannot call human-only MCP admin routes.'
)

AUTH_ADMIN = PERMISSIONS_BLOCK


def admin_description(
    *,
    lead: str,
    side_effects: str,
    sends_email: bool = False,
    destructive: bool = False,
    notes: str = '',
) -> str:
    parts = [lead.strip(), PERMISSIONS_BLOCK]
    parts.append(f'Side effects: {side_effects.strip()}')
    parts.append(f'Sends email: {"Yes" if sends_email else "No"}.')
    parts.append(f'Destructive: {"Yes" if destructive else "No"}.')
    if notes.strip():
        parts.append(notes.strip())
    return '\n\n'.join(parts)


def _error_response(description: str) -> OpenApiResponse:
    return OpenApiResponse(response=ErrorSerializer, description=description)


ADMIN_API_ERRORS = {
    400: _error_response(
        'Invalid query or body. Body uses `error_code` (often `validation_failed`) and optional '
        '`field_errors` mapping field names to stable codes (for example `required`, `invalid`).'
    ),
    401: _error_response('Missing or invalid Bearer token (`error_code`: `unauthorized`).'),
    403: _error_response(
        'Caller is authenticated but not allowed (`error_code`: `forbidden`). '
        'Common causes: wrong company, staff-only scope, or SCIM-managed resource guard.'
    ),
    404: _error_response('Resource not found (`error_code`: `not_found` or a domain-specific code).'),
    409: _error_response(
        'Conflict with current state (`error_code`: for example `last_company_owner`, `already_invited`).'
    ),
    429: _error_response('Rate limited (`error_code`: `rate_limited`). Retry after backing off.'),
}


def mcp_openapi_fields(operation_id: str) -> dict[str, str]:
    spec = MCP_SPECS.get(operation_id)
    if spec is None:
        raise KeyError(f'missing MCP OpenAPI registry entry for {operation_id}')
    return {
        'summary': spec.summary,
        'description': admin_description(
            lead=spec.lead,
            side_effects=spec.side_effects,
            sends_email=spec.sends_email,
            destructive=spec.destructive,
            notes=spec.notes,
        ),
    }


def admin_openapi_fields(
    *,
    summary: str,
    lead: str,
    side_effects: str,
    sends_email: bool = False,
    destructive: bool = False,
    sensitive: bool = False,
    notes: str = '',
) -> dict[str, str]:
    """Human-only admin routes (for example MCP agent pause) without ``x-mcp``."""
    _ = sensitive
    return {
        'summary': summary,
        'description': admin_description(
            lead=lead,
            side_effects=side_effects,
            sends_email=sends_email,
            destructive=destructive,
            notes=notes,
        ),
    }


def mcp_extend_schema_kwargs(operation_id: str) -> dict[str, object]:
    """Summary, description, and ``x-mcp`` extensions for allowlisted MCP tools."""
    if operation_id not in MCP_REQUIRED_OPERATION_IDS:
        raise KeyError(operation_id)
    payload = MCP_EXPLICIT_REGISTRY.get(operation_id)
    if payload is None:
        raise KeyError(f'mcp_tool registry missing {operation_id}; import openapi_mcp_registry first')
    return {
        **mcp_openapi_fields(operation_id),
        'operation_id': operation_id,
        'extensions': {'x-mcp': payload},
    }


if set(MCP_SPECS) != MCP_REQUIRED_OPERATION_IDS:
    missing = MCP_REQUIRED_OPERATION_IDS - set(MCP_SPECS)
    extra = set(MCP_SPECS) - MCP_REQUIRED_OPERATION_IDS
    raise AssertionError(f'MCP_SPECS drift: missing={sorted(missing)} extra={sorted(extra)}')
