"""Aggregated MCP gateway at Identity ``/mcp`` (downstream tools/list and tools/call)."""

from __future__ import annotations

import json
import logging
from typing import Any

import requests
from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, JsonResponse
from shellui_django.mcp.openapi_tools import tools_from_schema
from shellui_django.mcp.rate_limit import check_agent_rate_limit
from shellui_django.mcp.server import McpServer

from apps.agents.models import Agent
from apps.agents.services import list_mcp_services, service_allowed
from apps.agents.tokens import encode_access_token

logger = logging.getLogger(__name__)

_TOOLS_CACHE_PREFIX = 'mcp_gateway:tools:'
_TOOL_ROUTE_PREFIX = 'mcp_gateway:route:'


def _tools_cache_ttl() -> int:
    return int(getattr(settings, 'MCP_GATEWAY_TOOLS_CACHE_TTL_SECONDS', 30))


def _downstream_timeout() -> float:
    return float(getattr(settings, 'MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', 5))


def configured_service_urls() -> dict[str, str]:
    """Map service id to MCP URL from server settings only (SSRF-safe)."""
    return {str(item['id']): str(item['mcp_url']) for item in list_mcp_services()}


def _scope_service_ids(agent_claims: dict[str, Any]) -> set[str]:
    return {part for part in str(agent_claims.get('scope') or '').split() if part}


def _load_agent(agent_claims: dict[str, Any]) -> Agent | None:
    agent_id = agent_claims.get('agent_id')
    company_id = agent_claims.get('company_id')
    if not agent_id or company_id is None:
        return None
    try:
        company_id_int = int(company_id)
    except (TypeError, ValueError):
        return None
    try:
        return Agent.objects.get(pk=agent_id, company_id=company_id_int)
    except Agent.DoesNotExist:
        return None


def _public_tools(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tool in raw:
        if not isinstance(tool, dict):
            continue
        out.append({k: v for k, v in tool.items() if not str(k).startswith('_')})
    return out


def _fetch_remote_tools_list(*, mcp_url: str, bearer_token: str) -> list[dict[str, Any]] | None:
    cache_key = f'{_TOOLS_CACHE_PREFIX}{mcp_url}'
    cached = cache.get(cache_key)
    if isinstance(cached, list):
        return cached
    payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}
    try:
        response = requests.post(
            mcp_url,
            json=payload,
            headers={
                'Authorization': f'Bearer {bearer_token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            timeout=_downstream_timeout(),
        )
    except (requests.RequestException, OSError) as exc:
        logger.warning('MCP gateway tools/list transport error url=%s err=%s', mcp_url, type(exc).__name__)
        return None
    if response.status_code >= 400:
        logger.warning('MCP gateway tools/list HTTP %s url=%s', response.status_code, mcp_url)
        return None
    try:
        body = response.json()
    except ValueError:
        logger.warning('MCP gateway tools/list invalid JSON url=%s', mcp_url)
        return None
    tools = (body.get('result') or {}).get('tools')
    if not isinstance(tools, list):
        logger.warning('MCP gateway tools/list missing tools url=%s', mcp_url)
        return None
    public = _public_tools(tools)
    cache.set(cache_key, public, _tools_cache_ttl())
    return public


def _remember_route(export_name: str, *, service_id: str, downstream_name: str) -> None:
    cache.set(
        f'{_TOOL_ROUTE_PREFIX}{export_name}',
        {'service_id': service_id, 'downstream_name': downstream_name},
        _tools_cache_ttl(),
    )


def _lookup_route(tool_name: str) -> dict[str, str] | None:
    meta = cache.get(f'{_TOOL_ROUTE_PREFIX}{tool_name}')
    if isinstance(meta, dict) and meta.get('service_id') and meta.get('downstream_name'):
        return {'service_id': str(meta['service_id']), 'downstream_name': str(meta['downstream_name'])}
    return None


def merge_tool_catalog(
    local_tools: list[dict[str, Any]],
    remote_by_service: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    taken: set[str] = set()
    merged: list[dict[str, Any]] = []

    for tool in local_tools:
        name = str(tool.get('name') or '')
        if not name:
            continue
        taken.add(name)
        _remember_route(name, service_id='identity', downstream_name=name)
        merged.append(tool)

    for service_id, tools in remote_by_service.items():
        for tool in tools:
            downstream_name = str(tool.get('name') or '')
            if not downstream_name:
                continue
            export_name = downstream_name
            if export_name in taken:
                export_name = f'{service_id}__{downstream_name}'
            if export_name in taken:
                export_name = f'{service_id}__{downstream_name}__gateway'
            taken.add(export_name)
            _remember_route(export_name, service_id=service_id, downstream_name=downstream_name)
            if export_name == downstream_name:
                merged.append(tool)
            else:
                merged.append({**tool, 'name': export_name})
    return merged


def gateway_instructions(agent_claims: dict[str, Any], *, agent: Agent | None) -> str:
    configured = configured_service_urls()
    scope = _scope_service_ids(agent_claims)
    allowed_rows = set(agent.services_allowed or []) if agent else set()
    connected = sorted(sid for sid in scope if sid in allowed_rows and sid in configured)
    return (
        'Shellui Identity MCP gateway.\n'
        f'Connected services: {", ".join(connected) or "none"}.\n'
        'Remote tools run on the downstream service with the same agent access level and approvals.\n'
        'Use the list_services tool for per-service MCP URLs and resource-bound tokens.'
    )


class AggregatingMcpServer(McpServer):
    """Identity MCP server that aggregates downstream ``tools/list`` and forwards ``tools/call``."""

    def handle(self, request: HttpRequest, *, agent_claims: dict[str, Any] | None) -> JsonResponse:
        if request.method != 'POST':
            return JsonResponse({'error': 'method_not_allowed'}, status=405)
        if agent_claims is None:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        agent_id = str(agent_claims.get('agent_id') or '')
        if not agent_id:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        if check_agent_rate_limit(agent_id):
            return JsonResponse({'error': 'rate_limited'}, status=429)
        company_id = agent_claims.get('company_id')
        try:
            company_id_int = int(company_id) if company_id is not None else None
        except (TypeError, ValueError):
            company_id_int = None
        if self.identity_revocation_check and self.identity_revocation_check(agent_id, company_id_int):
            return JsonResponse({'error': 'agent_revoked'}, status=403)
        if not self._service_allowed(agent_claims, self.service_name):
            return JsonResponse({'error': 'forbidden'}, status=403)
        try:
            payload = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'invalid_json'}, status=400)
        method = payload.get('method')
        req_id = payload.get('id')
        params = payload.get('params') or {}
        if method == 'initialize':
            agent = _load_agent(agent_claims)
            return JsonResponse(
                self._result(
                    req_id,
                    {
                        'protocolVersion': '2024-11-05',
                        'capabilities': {'tools': {}},
                        'instructions': gateway_instructions(agent_claims, agent=agent),
                    },
                )
            )
        if method == 'tools/list':
            return self._aggregated_tools_list(req_id, agent_claims)
        if method == 'tools/call':
            forwarded = self._maybe_forward_tool_call(request, req_id, params, agent_claims)
            if forwarded is not None:
                return forwarded
        return super().handle(request, agent_claims=agent_claims)

    def _aggregated_tools_list(self, req_id: Any, agent_claims: dict[str, Any]) -> JsonResponse:
        agent = _load_agent(agent_claims)
        if agent is None:
            return JsonResponse(self._error(req_id, -32603, 'Forbidden'))
        scope = _scope_service_ids(agent_claims)
        allowed = scope & set(agent.services_allowed or [])
        schema = self.schema_provider()
        local = _public_tools(tools_from_schema(schema))
        remote: dict[str, list[dict[str, Any]]] = {}
        urls = configured_service_urls()
        for service_id, mcp_url in urls.items():
            if service_id == 'identity':
                continue
            if service_id not in allowed:
                continue
            token = encode_access_token(agent, resource=mcp_url)
            tools = _fetch_remote_tools_list(mcp_url=mcp_url, bearer_token=token)
            if tools is not None:
                remote[service_id] = tools
        tools = merge_tool_catalog(local, remote)
        return JsonResponse(self._result(req_id, {'tools': tools}))

    def _maybe_forward_tool_call(
        self,
        request: HttpRequest,
        req_id: Any,
        params: dict[str, Any],
        agent_claims: dict[str, Any],
    ) -> JsonResponse | None:
        tool_name = str(params.get('name') or '')
        if not tool_name:
            return None
        route = _lookup_route(tool_name)
        if route is None:
            schema = self.schema_provider()
            local_names = {str(t.get('name')) for t in tools_from_schema(schema)}
            if tool_name in local_names:
                return None
            return JsonResponse(self._error(req_id, -32602, 'Unknown tool'))
        service_id = route['service_id']
        if service_id == 'identity':
            return None
        scope = _scope_service_ids(agent_claims)
        if not service_allowed(list(scope), service_id):
            return JsonResponse(self._error(req_id, -32602, 'Forbidden'))
        agent = _load_agent(agent_claims)
        if agent is None or not service_allowed(agent.services_allowed or [], service_id):
            return JsonResponse(self._error(req_id, -32602, 'Forbidden'))
        mcp_url = configured_service_urls().get(service_id)
        if not mcp_url:
            return JsonResponse(self._error(req_id, -32602, 'Service unavailable'))
        token = encode_access_token(agent, resource=mcp_url)
        downstream_params = dict(params)
        downstream_params['name'] = route['downstream_name']
        rpc = {
            'jsonrpc': '2.0',
            'id': req_id,
            'method': 'tools/call',
            'params': downstream_params,
        }
        try:
            response = requests.post(
                mcp_url,
                json=rpc,
                headers={
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                timeout=_downstream_timeout(),
            )
        except (requests.RequestException, OSError) as exc:
            logger.warning(
                'MCP gateway tools/call transport error service=%s tool=%s err=%s',
                service_id,
                tool_name,
                type(exc).__name__,
            )
            return JsonResponse(
                self._result(
                    req_id,
                    {
                        'content': [{'type': 'text', 'text': 'Downstream service unavailable.'}],
                        'isError': True,
                    },
                )
            )
        if response.status_code >= 400:
            logger.warning(
                'MCP gateway tools/call HTTP %s service=%s tool=%s',
                response.status_code,
                service_id,
                tool_name,
            )
            return JsonResponse(
                self._result(
                    req_id,
                    {
                        'content': [{'type': 'text', 'text': 'Downstream service error.'}],
                        'isError': True,
                    },
                )
            )
        try:
            body = response.json()
        except ValueError:
            return JsonResponse(
                self._result(
                    req_id,
                    {'content': [{'type': 'text', 'text': 'Invalid downstream response.'}], 'isError': True},
                )
            )
        if not isinstance(body, dict):
            return JsonResponse(self._error(req_id, -32603, 'Invalid downstream response'))
        return JsonResponse(body)
