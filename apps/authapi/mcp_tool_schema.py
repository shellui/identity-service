"""Agent-facing MCP tool schemas.

shellui-django 0.5.1 advertises ``method`` and ``path`` as required arguments and
nests real fields under ``query``, ``body``, and ``path_params``. Identity publishes
a flat schema and still accepts the nested shape so an older gateway call succeeds.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from django.http import HttpRequest

IGNORED_QUERY_PARAMS = frozenset({'format'})
LEGACY_ARGUMENT_KEYS = frozenset({'method', 'path', 'query', 'body', 'path_params'})


def _clean_property(prop: dict[str, Any]) -> dict[str, Any]:
    cleaned = dict(prop)
    description = str(cleaned.get('description') or '')
    if description.lstrip().startswith('*'):
        cleaned.pop('description', None)
    return cleaned


def _operation_index(schema: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    index = {}
    for path_item in (schema.get('paths') or {}).values():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if not isinstance(operation, dict) or not operation.get('operationId'):
                continue
            index[(str(operation['operationId']), str(method).upper())] = operation
    return index


def _path_property(operation: dict[str, Any] | None, name: str) -> dict[str, Any]:
    prop: dict[str, Any] = {'type': 'string'}
    if not operation:
        return prop
    for param in operation.get('parameters') or []:
        if not isinstance(param, dict) or param.get('in') != 'path' or param.get('name') != name:
            continue
        schema = param.get('schema') if isinstance(param.get('schema'), dict) else {}
        prop = dict(schema) or prop
        description = param.get('description') or prop.get('description')
        if description:
            prop['description'] = description
        prop.setdefault('type', 'string')
        break
    return prop


def publish_tools(tools: list[dict[str, Any]], schema: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    operations = _operation_index(schema or {})
    published = []
    for tool in tools:
        meta = tool.get('_meta') or {}
        operation = operations.get((str(tool.get('name') or ''), str(meta.get('method') or '').upper()))
        raw_props = (tool.get('inputSchema') or {}).get('properties') or {}
        properties: dict[str, Any] = {}
        required: list[str] = []

        path_node = raw_props.get('path_params') or {}
        for name in path_node.get('required') or []:
            properties[name] = _clean_property(_path_property(operation, name))
            required.append(name)

        query_node = raw_props.get('query') or {}
        for name, prop in (query_node.get('properties') or {}).items():
            if name in IGNORED_QUERY_PARAMS:
                continue
            if name in properties:
                raise ValueError(f'colliding MCP argument {name} on {tool.get("name")}')
            properties[name] = _clean_property(prop)
        for name in query_node.get('required') or []:
            if name not in IGNORED_QUERY_PARAMS:
                required.append(name)

        body_node = raw_props.get('body') or {}
        for name, prop in (body_node.get('properties') or {}).items():
            if name in properties:
                raise ValueError(f'colliding MCP argument {name} on {tool.get("name")}')
            properties[name] = _clean_property(prop)
        required.extend(body_node.get('required') or [])

        input_schema: dict[str, Any] = {
            'type': 'object',
            'properties': properties,
            'additionalProperties': False,
        }
        if required:
            input_schema['required'] = required
        published.append(
            {
                'name': tool['name'],
                'description': str(tool.get('description') or '').strip(),
                'inputSchema': input_schema,
                'annotations': {
                    'readOnlyHint': bool(meta.get('read_only')),
                    'destructiveHint': bool(meta.get('destructive')),
                },
                '_meta': meta,
            }
        )
    return published


def _is_legacy_arguments(arguments: dict[str, Any]) -> bool:
    return any(key in arguments for key in LEGACY_ARGUMENT_KEYS)


def nest_arguments(arguments: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    """Map a flat tool call onto the nested shape shellui-django validates."""
    if _is_legacy_arguments(arguments):
        return arguments
    path_names = [str(name) for name in (meta.get('path_params') or [])]
    query_fields = [str(name) for name in (meta.get('query_fields') or []) if name not in IGNORED_QUERY_PARAMS]
    body_fields = [str(name) for name in (meta.get('body_fields') or [])]
    path_params: dict[str, Any] = {}
    query: dict[str, Any] = {}
    body: dict[str, Any] = {}
    unknown: dict[str, Any] = {}
    for key, value in arguments.items():
        if key in path_names:
            path_params[key] = value
        elif key in query_fields:
            query[key] = value
        elif key in body_fields:
            body[key] = value
        else:
            unknown[key] = value
    nested: dict[str, Any] = {'path': meta.get('path'), 'method': meta.get('method')}
    if path_names:
        nested['path_params'] = path_params
    if query_fields:
        nested['query'] = query
    if body_fields:
        body.update(unknown)
        nested['body'] = body
    elif unknown and query_fields:
        query.update(unknown)
        nested['query'] = query
    elif unknown:
        nested['body'] = unknown
    return nested


def rewrite_tool_call_arguments(request: HttpRequest, tools: list[dict[str, Any]]) -> None:
    if request.method != 'POST':
        return
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    if not isinstance(payload, dict) or payload.get('method') != 'tools/call':
        return
    params = payload.get('params')
    if not isinstance(params, dict):
        return
    arguments = params.get('arguments')
    if not isinstance(arguments, dict):
        return
    name = str(params.get('name') or '')
    tool = next((item for item in tools if item.get('name') == name), None)
    if tool is None:
        return
    params['arguments'] = nest_arguments(arguments, tool.get('_meta') or {})
    payload['params'] = params
    encoded = json.dumps(payload).encode('utf-8')
    request._body = encoded  # noqa: SLF001
    request.META['CONTENT_LENGTH'] = str(len(encoded))


def _encode_query_value(value: Any) -> str:
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (list, tuple)):
        return ','.join(_encode_query_value(item) for item in value)
    return str(value)


def append_query(path: str, query_params: Any) -> str:
    """Put MCP query arguments on the request URL. ``format`` is content negotiation."""
    if not isinstance(query_params, dict) or not query_params:
        return path
    pairs = []
    for key, value in query_params.items():
        if key in IGNORED_QUERY_PARAMS or value is None:
            continue
        pairs.append((str(key), _encode_query_value(value)))
    if not pairs:
        return path
    encoded = urlencode(pairs)
    parts = urlsplit(path)
    query = encoded if not parts.query else f'{parts.query}&{encoded}'
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
