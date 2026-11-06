"""Shared handler for MCP OAuth token requests (authorization_code, refresh_token, agent exchange).

Used by ``/oauth/mcp/token`` and regional ``POST /oauth/token`` so both paths share one implementation.
Parsed bodies preserve repeated form keys (see :func:`apps.agents.oauth_request_body.parse_oauth_post_body`).
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone

from apps.agents.exchange import GRANT_TYPE as AGENT_EXCHANGE_GRANT, agent_exchange_enabled, handle_agent_token_exchange
from apps.agents.models import Agent, McpAuthorizationCode, McpOAuthClient
from apps.agents.oauth_codes import hash_authorization_code, issue_mcp_authorization_code
from apps.agents.oauth_redirect import validate_mcp_redirect_uri
from apps.agents.oauth_request_body import oauth_error, parse_oauth_post_body
from apps.agents.mcp_resources import resolve_mcp_resource
from apps.agents.staff import is_mcp_oauth_refused_user
from apps.agents.tokens import encode_access_token, issue_agent_refresh, refresh_agent_access
from apps.authapi.client_pkce import verify_client_pkce


def handle_mcp_token_request(request) -> JsonResponse:
    """Dispatch MCP token endpoint: RFC 8693 agent exchange, refresh, or authorization_code."""
    body, parse_err = parse_oauth_post_body(request)
    if parse_err is not None:
        return parse_err
    assert body is not None
    grant = str(body.get('grant_type') or '').strip()
    if not grant:
        return oauth_error('invalid_request')
    if grant == AGENT_EXCHANGE_GRANT:
        if not agent_exchange_enabled():
            return JsonResponse({}, status=404)
        return handle_agent_token_exchange(request, data=body)
    if grant == 'refresh_token':
        refresh = str(body.get('refresh_token') or '')
        resource_url, _service_id = resolve_mcp_resource(str(body.get('resource') or ''))
        if not resource_url:
            return JsonResponse({'error': 'invalid_target'}, status=400)
        pair = refresh_agent_access(refresh, resource=resource_url)
        if not pair:
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        access, new_refresh = pair
        return JsonResponse(
            {
                'access_token': access,
                'token_type': 'Bearer',
                'expires_in': int(getattr(settings, 'MCP_ACCESS_TOKEN_LIFETIME', timedelta(minutes=15)).total_seconds()),
                'refresh_token': new_refresh,
            }
        )
    if grant != 'authorization_code':
        return oauth_error('unsupported_grant_type')
    code = str(body.get('code') or '').strip()
    redirect_uri = str(body.get('redirect_uri') or '').strip()
    client_id = str(body.get('client_id') or '').strip()
    verifier = body.get('code_verifier')
    try:
        client = McpOAuthClient.objects.get(client_id=client_id)
    except McpOAuthClient.DoesNotExist:
        return JsonResponse({'error': 'invalid_client'}, status=401)
    code_digest = hash_authorization_code(code)
    canonical_redirect, rerr = validate_mcp_redirect_uri(request, redirect_uri)
    if rerr or not canonical_redirect:
        return JsonResponse({'error': 'invalid_grant'}, status=400)
    redirect_uri = canonical_redirect
    with transaction.atomic():
        try:
            row = (
                McpAuthorizationCode.objects.select_for_update()
                .select_related('agent__company', 'user')
                .get(code=code_digest, client=client)
            )
        except McpAuthorizationCode.DoesNotExist:
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        if row.redeemed_at is not None or row.expires_at <= timezone.now():
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        if row.redirect_uri != redirect_uri:
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        agent = row.agent
        resource_url, service_id = resolve_mcp_resource(str(body.get('resource') or ''))
        if not resource_url or row.resource != resource_url:
            return JsonResponse({'error': 'invalid_target'}, status=400)
        if not service_id or service_id not in (agent.services_allowed or []):
            return JsonResponse({'error': 'access_denied'}, status=403)
        message, _code = verify_client_pkce(
            code_challenge=row.code_challenge,
            code_verifier=verifier,
            required=True,
        )
        if message:
            return JsonResponse({'error': 'invalid_grant', 'error_description': message}, status=400)
        if is_mcp_oauth_refused_user(row.user):
            return JsonResponse({'error': 'access_denied'}, status=403)
        if not agent.is_active:
            return JsonResponse({'error': 'access_denied'}, status=403)
        row.redeemed_at = timezone.now()
        row.save(update_fields=['redeemed_at'])
        bound_resource = row.resource
    try:
        access = encode_access_token(agent, resource=bound_resource)
    except ValueError:
        return JsonResponse({'error': 'invalid_grant'}, status=400)
    refresh, _session = issue_agent_refresh(agent, resource=bound_resource)
    return JsonResponse(
        {
            'access_token': access,
            'token_type': 'Bearer',
            'expires_in': int(getattr(settings, 'MCP_ACCESS_TOKEN_LIFETIME', timedelta(minutes=15)).total_seconds()),
            'refresh_token': refresh,
        }
    )
