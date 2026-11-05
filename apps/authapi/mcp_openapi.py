"""OpenAPI ``x-mcp`` markers for Shellui MCP tools on ``POST /mcp``."""

from __future__ import annotations

from typing import Any

# Paths that must not appear in the published OpenAPI document.
MCP_EXCLUDED_PATH_PREFIXES: tuple[str, ...] = (
    '/api/v1/mcp/internal/',
    '/api/v1/scheduled-jobs',
    '/api/v1/provisioning/',
)

# Operation ids that must never carry ``x-mcp`` (human-only, session, staff-only, or internal).
MCP_FORBIDDEN_OPERATION_IDS: frozenset[str] = frozenset(
    {
        'api_v1_metrics_all_retrieve',
        'api_v1_scheduled_jobs_list',
        'api_v1_scheduled_jobs_runs_list',
        'api_v1_scheduled_jobs_runs_retrieve',
        'api_v1_provisioning_companies_list',
        'api_v1_provisioning_companies_create',
        'api_v1_provisioning_companies_retrieve',
        'api_v1_provisioning_companies_partial_update',
        'api_v1_provisioning_companies_destroy',
        'api_v1_provisioning_companies_limits_update',
        'api_v1_mcp_agents_list',
        'api_v1_mcp_agents_pause',
        'api_v1_mcp_agents_revoke',
        'api_v1_mcp_approvals_list',
        'api_v1_mcp_approvals_retrieve',
        'api_v1_mcp_approvals_approve',
        'api_v1_mcp_approvals_reject',
        'api_v1_mcp_approvals_decide',
        'api_v1_mcp_call_logs_list',
        'api_v1_mcp_internal_mcp_revocations_list',
        'api_v1_mcp_internal_mcp_approval_requests_create',
        'api_v1_mcp_internal_mcp_approval_state_create',
        'api_v1_mcp_internal_mcp_approval_consume_create',
        'api_v1_mcp_internal_mcp_approval_decide_create',
        'api_v1_mcp_internal_mcp_approval_session_check_create',
        'api_v1_mcp_internal_mcp_approval_session_revoke_create',
        'api_v1_mcp_internal_mcp_call_logs_create',
    }
)

# Company-owner admin APIs that must be explicitly decorated with ``mcp_tool`` to become MCP tools.
MCP_REQUIRED_OPERATION_IDS: frozenset[str] = frozenset(
    {
        'api_v1_actions_deliveries_list',
        'api_v1_actions_deliveries_requeue',
        'api_v1_actions_deliveries_retrieve',
        'api_v1_actions_events_list',
        'api_v1_actions_rules_create',
        'api_v1_actions_rules_destroy',
        'api_v1_actions_rules_list',
        'api_v1_actions_rules_partial_update',
        'api_v1_actions_rules_retrieve',
        'api_v1_actions_rules_rotate_secret',
        'api_v1_actions_rules_send_test',
        'api_v1_auth_methods_partial_update',
        'api_v1_auth_methods_retrieve',
        'api_v1_auth_methods_update',
        'api_v1_companies_list',
        'api_v1_companies_partial_update',
        'api_v1_companies_retrieve',
        'api_v1_companies_update',
        'api_v1_events_list',
        'api_v1_events_retention_retrieve',
        'api_v1_events_retrieve',
        'api_v1_events_types_list',
        'api_v1_groups_create',
        'api_v1_groups_destroy',
        'api_v1_groups_list',
        'api_v1_groups_partial_update',
        'api_v1_groups_retrieve',
        'api_v1_groups_update',
        'api_v1_hosting_oauth_redirects_destroy',
        'api_v1_hosting_oauth_redirects_update',
        'api_v1_invitations_create',
        'api_v1_invitations_destroy',
        'api_v1_invitations_list',
        'api_v1_invitations_revoke',
        'api_v1_mcp_services_list',
        'api_v1_oauth_clients_create',
        'api_v1_oauth_clients_destroy',
        'api_v1_oauth_clients_list',
        'api_v1_oauth_clients_retrieve',
        'api_v1_oauth_clients_update',
        'api_v1_oauth_provider_catalog_retrieve',
        'api_v1_oauth_redirects_create',
        'api_v1_oauth_redirects_destroy',
        'api_v1_oauth_redirects_list',
        'api_v1_oauth_redirects_partial_update',
        'api_v1_oauth_redirects_retrieve',
        'api_v1_oauth_social_apps_create',
        'api_v1_oauth_social_apps_destroy',
        'api_v1_oauth_social_apps_list',
        'api_v1_oauth_social_apps_update',
        'api_v1_personal_access_tokens_create',
        'api_v1_personal_access_tokens_list',
        'api_v1_personal_access_tokens_revoke',
        'api_v1_scim_status',
        'api_v1_scim_tokens_create',
        'api_v1_scim_tokens_list',
        'api_v1_scim_tokens_revoke',
        'api_v1_users_audience',
        'api_v1_users_destroy',
        'api_v1_users_list',
        'api_v1_users_retrieve',
        'api_v1_users_update',
    }
)

# OpenAPI component properties that must carry ``x-mcp-secret`` (plaintext secrets or key material).
MCP_REQUIRED_SECRET_SCHEMA_PROPERTIES: frozenset[tuple[str, str]] = frozenset(
    {
        ('ActionRuleCreate', 'secret'),
        ('ShellUIAdminOAuthSocialAppCreate', 'client_secret'),
        ('ShellUIAdminOAuthSocialAppUpdate', 'client_secret'),
    }
)

# Populated only by ``mcp_tool(...)`` at import time (strict allowlist).
MCP_EXPLICIT_REGISTRY: dict[str, dict[str, Any]] = {}


def _mcp_payload(*, read_only: bool, destructive: bool = False, sensitive: bool = False) -> dict[str, Any]:
    return {
        'read_only': read_only,
        'destructive': destructive,
        'sensitive': sensitive,
    }


def mcp_tool(
    *,
    operation_id: str,
    read_only: bool,
    destructive: bool = False,
    sensitive: bool = False,
) -> dict[str, Any]:
    """Register an MCP tool and return ``extend_schema`` kwargs (only explicit decoration exposes a tool)."""
    if operation_id in MCP_FORBIDDEN_OPERATION_IDS:
        raise ValueError(f'mcp_tool cannot tag forbidden operation: {operation_id}')
    payload = _mcp_payload(read_only=read_only, destructive=destructive, sensitive=sensitive)
    existing = MCP_EXPLICIT_REGISTRY.get(operation_id)
    if existing is not None and existing != payload:
        raise ValueError(f'mcp_tool called twice with different flags for {operation_id}')
    MCP_EXPLICIT_REGISTRY[operation_id] = payload
    return {'extensions': {'x-mcp': payload}}


def mcp_extension(operation: dict[str, Any]) -> dict[str, Any] | None:
    raw = operation.get('x-mcp')
    if isinstance(raw, dict):
        return raw
    extensions = operation.get('extensions') or {}
    nested = extensions.get('x-mcp')
    return nested if isinstance(nested, dict) else None


def validate_mcp_schema(schema: dict[str, Any]) -> None:
    paths = schema.get('paths') or {}
    for prefix in MCP_EXCLUDED_PATH_PREFIXES:
        for path in paths:
            if path.startswith(prefix):
                raise AssertionError(f'excluded path must not appear in OpenAPI: {path}')

    tagged_in_schema: dict[str, dict[str, Any]] = {}
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for prefix in MCP_EXCLUDED_PATH_PREFIXES:
            if path.startswith(prefix):
                if any(mcp_extension(op) for op in path_item.values() if isinstance(op, dict)):
                    raise AssertionError(f'x-mcp must not appear under excluded path: {path}')
        for operation in path_item.values():
            if not isinstance(operation, dict) or 'operationId' not in operation:
                continue
            op_id = operation['operationId']
            ext = mcp_extension(operation)
            if op_id in MCP_FORBIDDEN_OPERATION_IDS and ext is not None:
                raise AssertionError(f'forbidden operation must not be tagged x-mcp: {op_id}')
            if ext is not None:
                tagged_in_schema[op_id] = ext

    if set(tagged_in_schema) != set(MCP_EXPLICIT_REGISTRY):
        raise AssertionError(
            f'x-mcp in schema must match mcp_tool registry only: '
            f'schema={sorted(tagged_in_schema)} registry={sorted(MCP_EXPLICIT_REGISTRY)}'
        )
    for op_id, payload in tagged_in_schema.items():
        if payload != MCP_EXPLICIT_REGISTRY[op_id]:
            raise AssertionError(f'x-mcp payload mismatch for {op_id}: {payload} != {MCP_EXPLICIT_REGISTRY[op_id]}')

    missing_decorators = MCP_REQUIRED_OPERATION_IDS - set(MCP_EXPLICIT_REGISTRY)
    if missing_decorators:
        raise AssertionError(f'required operations missing mcp_tool decoration: {sorted(missing_decorators)}')

    extra_decorators = set(MCP_EXPLICIT_REGISTRY) - MCP_REQUIRED_OPERATION_IDS
    if extra_decorators:
        raise AssertionError(f'mcp_tool on operations outside allowlist: {sorted(extra_decorators)}')


def validate_mcp_secret_fields(schema: dict[str, Any]) -> None:
    components = schema.get('components') or {}
    schemas = components.get('schemas') or {}
    missing = []
    for component, prop in MCP_REQUIRED_SECRET_SCHEMA_PROPERTIES:
        definition = schemas.get(component) or {}
        props = definition.get('properties') or {}
        field = props.get(prop) or {}
        if field.get('x-mcp-secret') is not True:
            missing.append(f'{component}.{prop}')
    if missing:
        raise AssertionError(f'schema properties missing x-mcp-secret: {sorted(missing)}')
