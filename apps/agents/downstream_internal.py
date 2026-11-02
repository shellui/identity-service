"""Mint downstream MCP access tokens for the AI service connector (RS256 delegation)."""

from __future__ import annotations

from django.conf import settings
from django.core.cache import cache
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from shellui_django.mcp.delegation import (
    DOWNSTREAM_TOKEN_REQUEST_LEEWAY_SECONDS,
    DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS,
    DownstreamTokenRequestError,
    verify_downstream_token_request,
)
from shellui_django.mcp.identity_jwks import IdentityJwksError
from shellui_django.mcp.rate_limit import check_agent_rate_limit
from shellui_django.mcp.resources import normalize_resource_indicator

from apps.agents.ai_service_config import (
    ai_service_delegation_enabled,
    ai_service_issuer,
    resolve_ai_service_verification_material,
)
from apps.agents.mcp_resources import catalog_resources_by_url
from apps.agents.models import Agent
from apps.agents.revocation import blocked_agent_ids
from apps.agents.services import service_allowed
from apps.agents.tokens import encode_access_token
from apps.authapi.throttling import check_rate_limit

_JTI_CACHE_PREFIX = 'mcp_downstream_jti:'


def _bearer_token(request) -> str:
    auth = request.headers.get('Authorization') or ''
    if auth.lower().startswith('bearer '):
        return auth[7:].strip()
    return ''


def _body_field(body: dict, name: str) -> str:
    value = body.get(name)
    if value is None:
        return ''
    return str(value).strip()


def _global_downstream_rate_limited(request) -> Response | None:
    limits = getattr(settings, 'MCP_RATE_LIMITS', None) or {}
    spec = limits.get('mcp_downstream_mint') or limits.get('default') or {'limit': 120, 'window': 60}
    return check_rate_limit(
        request,
        scope='mcp_downstream_mint',
        identity='global',
        limit=int(spec['limit']),
        window=int(spec['window']),
    )


def _consume_request_jti(jti: str) -> bool:
    ttl = DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS + DOWNSTREAM_TOKEN_REQUEST_LEEWAY_SECONDS + 30
    key = f'{_JTI_CACHE_PREFIX}{jti}'
    return cache.add(key, 1, timeout=ttl)


class McpDownstreamAccessTokenView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        if not ai_service_delegation_enabled():
            return Response(status=status.HTTP_404_NOT_FOUND)
        limited = _global_downstream_rate_limited(request)
        if limited is not None:
            return limited
        raw = _bearer_token(request)
        try:
            material = resolve_ai_service_verification_material()
            claims = verify_downstream_token_request(raw, material, ai_service_issuer())
        except (DownstreamTokenRequestError, IdentityJwksError) as exc:
            message = getattr(exc, 'message', str(exc))
            code = getattr(exc, 'status', status.HTTP_401_UNAUTHORIZED)
            return Response({'error': message}, status=code)

        body = request.data if isinstance(request.data, dict) else {}
        agent_id = _body_field(body, 'agent_id') or str(claims.get('agent_id') or '').strip()
        company_raw = body.get('company_id') if body.get('company_id') is not None else claims.get('company_id')
        resource = normalize_resource_indicator(
            _body_field(body, 'resource') or str(claims.get('resource') or '')
        )

        if str(claims.get('agent_id') or '').strip() != agent_id:
            return Response({'error': 'Request body does not match delegation JWT.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            claim_company = int(claims.get('company_id'))
            body_company = int(company_raw)
        except (TypeError, ValueError):
            return Response({'error': 'Invalid company_id.'}, status=status.HTTP_400_BAD_REQUEST)
        if claim_company != body_company:
            return Response({'error': 'Request body does not match delegation JWT.'}, status=status.HTTP_400_BAD_REQUEST)
        claim_resource = normalize_resource_indicator(str(claims.get('resource') or ''))
        if claim_resource != resource:
            return Response({'error': 'Request body does not match delegation JWT.'}, status=status.HTTP_400_BAD_REQUEST)

        if check_agent_rate_limit(agent_id):
            return Response({'error': 'rate_limited'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        catalog = catalog_resources_by_url()
        if resource not in catalog:
            return Response({'error': 'Resource is not configured.'}, status=status.HTTP_403_FORBIDDEN)

        try:
            agent = Agent.objects.get(pk=agent_id, company_id=body_company)
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)

        if not agent.is_active:
            return Response({'error': 'Agent inactive.'}, status=status.HTTP_403_FORBIDDEN)
        if str(agent.id) in set(blocked_agent_ids(company_id=body_company)):
            return Response({'error': 'Agent revoked.'}, status=status.HTTP_403_FORBIDDEN)

        service_id = catalog[resource]
        if not service_allowed(agent.services_allowed or [], service_id):
            return Response({'error': 'Resource not allowed for agent.'}, status=status.HTTP_403_FORBIDDEN)

        jti = str(claims.get('jti') or '').strip()
        if not jti or not _consume_request_jti(jti):
            return Response({'error': 'Delegation request already used.'}, status=status.HTTP_401_UNAUTHORIZED)

        access_token = encode_access_token(agent, resource=resource)
        return Response({'access_token': access_token})
