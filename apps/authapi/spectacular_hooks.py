"""drf-spectacular hooks for Shellui MCP."""

from __future__ import annotations

from typing import Any

from apps.authapi.mcp_openapi import (
    MCP_EXCLUDED_PATH_PREFIXES,
    MCP_REQUIRED_SECRET_SCHEMA_PROPERTIES,
    mcp_extension,
)
from shellui_django.mcp.decorators import MCP_TOOL_TAG

MCP_DESTRUCTIVE_TAG = 'mcp-destructive'


def preprocessing_exclude_internal_endpoints(endpoints):
    """Drop staff-only and internal routes from the published schema."""
    filtered = []
    for path, path_regex, method, callback in endpoints:
        if any(str(path).startswith(prefix) for prefix in MCP_EXCLUDED_PATH_PREFIXES):
            continue
        filtered.append((path, path_regex, method, callback))
    return filtered


def postprocess_mcp_secret_markers(result: dict[str, Any], **kwargs) -> dict[str, Any]:
    components = (result.get('components') or {}).get('schemas') or {}
    for component, prop in MCP_REQUIRED_SECRET_SCHEMA_PROPERTIES:
        definition = components.get(component) or {}
        props = definition.get('properties') or {}
        field = props.get(prop)
        if isinstance(field, dict):
            field['x-mcp-secret'] = True
    return result


def postprocess_mcp_tool_tags(result: dict[str, Any], **kwargs) -> dict[str, Any]:
    """Expose only ``mcp_tool``-registered operations as MCP tools (``mcp-tools`` tag)."""
    result = mcp_schema_for_server(result)
    return postprocess_mcp_secret_markers(result, **kwargs)


def mcp_schema_for_server(schema: dict[str, Any]) -> dict[str, Any]:
    paths = schema.get('paths') or {}
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            ext = mcp_extension(operation)
            if ext is None:
                continue
            tags = list(operation.get('tags') or [])
            if MCP_TOOL_TAG not in tags:
                tags.append(MCP_TOOL_TAG)
            if ext.get('destructive') and MCP_DESTRUCTIVE_TAG not in tags:
                tags.append(MCP_DESTRUCTIVE_TAG)
            operation['tags'] = tags
    return schema
