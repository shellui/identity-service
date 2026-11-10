"""Regional ``POST /oauth/token`` dispatches MCP OAuth and user token exchange (RFC 8693)."""

from __future__ import annotations

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from apps.agents.exchange import GLOBAL_AGENT_MCP_AUTHORITY, GLOBAL_AGENT_TOKEN_TYPE
from apps.agents.json_strict import decode_jwt_payload_unverified
from apps.agents.mcp_signin import plain_response
from apps.agents.oauth_request_body import parse_oauth_post_body
from apps.agents.oauth_token_dispatch import handle_mcp_token_request
from apps.authapi.throttling import check_rate_limit
from apps.federation.exchange import GRANT_TYPE, handle_token_exchange
from apps.federation.role import is_global, is_region
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response


class _TokenExchangeRequestProxy:
    """``handle_token_exchange`` expects ``request.data`` (DRF); forward everything else to Django ``request``."""

    __slots__ = ('_request', 'data')

    def __init__(self, request, data: dict):
        object.__setattr__(self, '_request', request)
        object.__setattr__(self, 'data', data)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, '_request'), name)


@csrf_exempt
@require_POST
def unified_regional_oauth_token(request) -> JsonResponse | HttpResponse:
    """Region: MCP grants (code, refresh, agent exchange), or user session token exchange (RFC 8693)."""
    limited = plain_response(check_rate_limit(request, scope='token_exchange'))
    if limited:
        return limited

    body, parse_err = parse_oauth_post_body(request)
    if parse_err is not None:
        return parse_err
    data = body or {}
    grant = str(data.get('grant_type') or '').strip()

    if grant != GRANT_TYPE:
        return handle_mcp_token_request(request)

    subject = str(data.get('subject_token') or '').strip()
    unverified = decode_jwt_payload_unverified(subject) or {}
    is_agent_exchange = unverified.get('token_type') == GLOBAL_AGENT_TOKEN_TYPE or unverified.get(
        'mcp_authority'
    ) == GLOBAL_AGENT_MCP_AUTHORITY
    if is_agent_exchange:
        return handle_mcp_token_request(request)

    response = handle_token_exchange(_TokenExchangeRequestProxy(request, data))
    if isinstance(response, Response):
        response.accepted_renderer = JSONRenderer()
        response.accepted_media_type = 'application/json'
        response.renderer_context = {}
        return response.render()
    return response


@csrf_exempt
@require_POST
def oauth_token_dispatch(request) -> JsonResponse | HttpResponse:
    """``POST /oauth/token``: discovery `token_endpoint`; behavior depends on instance role."""
    # Shellui CLI device grants are app sessions, on every instance role. Other grants keep
    # the role-specific handler below (OpenID on global, MCP and user exchange on a region).
    body, parse_err = parse_oauth_post_body(request)
    if parse_err is None and body is not None:
        from apps.agents.oauth_device import DEVICE_CODE_GRANT
        from apps.authapi.cli_device import CLI_CLIENT_ID, handle_cli_device_code_grant

        grant = str(body.get('grant_type') or '').strip()
        client_id = str(body.get('client_id') or '').strip()
        if grant == DEVICE_CODE_GRANT and client_id == CLI_CLIENT_ID:
            limited = plain_response(check_rate_limit(request, scope='token_exchange'))
            if limited:
                return limited
            return handle_cli_device_code_grant(body)
    if is_global():
        from apps.federation.provider import TokenView

        return TokenView.as_view()(request)
    if is_region():
        return unified_regional_oauth_token(request)
    limited = plain_response(check_rate_limit(request, scope='token_exchange'))
    if limited:
        return limited
    return handle_mcp_token_request(request)
