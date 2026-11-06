"""Personal MCP agent tokens for company members (human bearer only)."""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.agents.models import Agent, McpCallLog, PersonalAgentCredential
from apps.agents.mcp_resources import company_mcp_resource_url, global_mcp_url, mcp_enabled_for_company
from apps.agents.mcp_setup_session_ttl import session_allow_ttl_bound_seconds
from apps.agents.mcp_setup_session_ttl import session_ttl_seconds as mcp_default_approval_session_ttl_seconds
from apps.agents.permissions import require_company_member
from apps.agents.personal_agent_tokens import (
    create_personal_agent_credential,
    normalize_personal_agent_services,
    parse_required_expires_at,
    personal_agent_max_lifetime,
)
from apps.agents.agent_permissions import invalidate_agent_session_grants
from apps.agents.tokens import revoke_all_agent_refresh_sessions
from apps.authapi.openapi_admin import ADMIN_API_ERRORS, admin_openapi_fields
from apps.authapi.serializers import ShellUIOpenAPISerializer
from apps.authapi.throttling import check_rate_limit


def _setup_from_access_token(request, company) -> tuple[bool | None, int | None]:
    """Setup window from validated ShellUI access token (must match this company)."""
    token = getattr(request, 'auth', None)
    if token is None or not hasattr(token, 'get'):
        return None, None
    cid = token.get('setup_context_company_id')
    exp_unix = token.get('setup_expires_at')
    if cid is None or exp_unix is None:
        return None, None
    try:
        if int(cid) != int(company.id):
            return None, None
    except (TypeError, ValueError):
        return None, None
    try:
        exp_i = int(exp_unix)
    except (TypeError, ValueError):
        return None, None
    now_i = int(timezone.now().timestamp())
    return exp_i > now_i, exp_i


def _activity_retention_cutoff():
    days = int(getattr(settings, 'MCP_AGENT_ACTIVITY_RETENTION_DAYS', 90) or 90)
    days = max(1, min(days, 3660))
    return timezone.now() - timedelta(days=days)


def _agent_kind(agent: Agent) -> str:
    if hasattr(agent, 'personal_credential') and agent.personal_credential is not None:
        return 'personal'
    return 'oauth'


def _agent_summary(agent: Agent) -> dict:
    cred = getattr(agent, 'personal_credential', None)
    return {
        'id': str(agent.id),
        'kind': _agent_kind(agent),
        'name': agent.name,
        'access_mode': agent.access_mode,
        'read_level': agent.read_level,
        'allow_destructive_without_asking': agent.allow_destructive_without_asking,
        'services_allowed': agent.services_allowed,
        'expires_at': agent.expires_at.isoformat() if agent.expires_at else None,
        'paused_at': agent.paused_at.isoformat() if agent.paused_at else None,
        'revoked_at': agent.revoked_at.isoformat() if agent.revoked_at else None,
        'is_active': agent.is_active,
        'created_at': agent.created_at.isoformat(),
        'oauth_client_id': agent.oauth_client.client_id if agent.oauth_client_id else None,
        'personal_token_id': str(cred.id) if cred is not None else None,
    }


class PersonalAgentTokenCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    services = serializers.ListField(child=serializers.CharField(), allow_empty=False)
    access_mode = serializers.ChoiceField(choices=[c[0] for c in Agent.ACCESS_CHOICES], default=Agent.ACCESS_ASK)
    read_level = serializers.ChoiceField(choices=[c[0] for c in Agent.READ_CHOICES], default=Agent.READ_SAFE)
    allow_destructive = serializers.BooleanField(default=False)
    expires_at = serializers.DateTimeField()


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-personal'],
        operation_id='api_v1_mcp_personal_status',
        **admin_openapi_fields(
            summary='MCP availability for a company',
            lead='Returns whether the ai-service gateway is configured and the per-company MCP URL.',
            side_effects='Read-only.',
        ),
        responses={200: OpenApiResponse(description='MCP status'), **ADMIN_API_ERRORS},
    ),
)
class PersonalMcpStatusView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _user, company, err = require_company_member(request)
        if err:
            return err
        url = company_mcp_resource_url(company.id)
        setup_active, setup_expires_at_unix = _setup_from_access_token(request, company)
        lo, hi = session_allow_ttl_bound_seconds()
        payload = {
            'mcp_enabled': bool(url),
            'mcp_url': url,
            'global_mcp_url': global_mcp_url(),
            'approval_session_ttl_seconds': mcp_default_approval_session_ttl_seconds(),
            'setup_session_ttl_min_seconds': lo,
            'setup_session_ttl_max_seconds': hi,
        }
        if setup_active is not None:
            payload['setup_active'] = setup_active
        if setup_expires_at_unix is not None:
            payload['setup_expires_at'] = setup_expires_at_unix
        return Response(payload)


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-personal'],
        operation_id='api_v1_mcp_personal_agents_list',
        **admin_openapi_fields(
            summary='List your MCP agents',
            lead='OAuth-connected and personal agents you created for this company.',
            side_effects='Read-only.',
        ),
        responses={200: OpenApiResponse(description='Agents'), **ADMIN_API_ERRORS},
    ),
)
class PersonalAgentListView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        user, company, err = require_company_member(request)
        if err:
            return err
        qs = (
            Agent.objects.filter(company=company, created_by=user)
            .select_related('oauth_client', 'personal_credential')
            .order_by('-created_at')[:200]
        )
        return Response({'agents': [_agent_summary(a) for a in qs]})


@extend_schema_view(
    post=extend_schema(
        tags=['mcp-personal'],
        operation_id='api_v1_mcp_personal_agents_create',
        **admin_openapi_fields(
            summary='Create a personal MCP agent token',
            lead='Mints a long-lived agent bearer JWT for the company MCP gateway. The token is returned once.',
            side_effects='Creates an agent row and personal credential (jti hash only).',
            sensitive=True,
        ),
        request=PersonalAgentTokenCreateSerializer,
        responses={201: OpenApiResponse(description='Agent and access token'), **ADMIN_API_ERRORS},
    ),
)
class PersonalAgentTokenCreateView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def post(self, request):
        limited = check_rate_limit(request, scope='mcp_personal_agent')
        if limited is not None:
            return limited
        user, company, err = require_company_member(request)
        if err:
            return err
        if not mcp_enabled_for_company(company.id):
            return Response({'error': 'MCP is not enabled for this company.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = PersonalAgentTokenCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        services = normalize_personal_agent_services(list(data['services']))
        if not services:
            return Response({'error': 'At least one valid service is required.'}, status=status.HTTP_400_BAD_REQUEST)
        expires_at = parse_required_expires_at(data['expires_at'])
        if expires_at is None:
            return Response({'error': 'expires_at is required.'}, status=status.HTTP_400_BAD_REQUEST)
        max_exp = timezone.now() + personal_agent_max_lifetime()
        if expires_at > max_exp:
            return Response({'error': 'expires_at exceeds the maximum allowed lifetime.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            row, access_token = create_personal_agent_credential(
                user=user,
                company=company,
                name=data['name'],
                services=services,
                access_mode=data['access_mode'],
                read_level=data['read_level'],
                allow_destructive=bool(data['allow_destructive']),
                expires_at=expires_at,
            )
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {
                'agent': _agent_summary(row.agent),
                'access_token': access_token,
                'token_type': 'bearer',
                'expires_at': row.expires_at.isoformat(),
                'resource': company_mcp_resource_url(company.id),
            },
            status=status.HTTP_201_CREATED,
        )


@extend_schema_view(
    post=extend_schema(
        tags=['mcp-personal'],
        operation_id='api_v1_mcp_personal_agents_revoke',
        **admin_openapi_fields(
            summary='Revoke your MCP agent',
            lead='Revokes an OAuth or personal agent you created. Takes effect immediately.',
            side_effects='Sets revoked_at on the agent and revokes refresh sessions.',
            destructive=True,
        ),
        responses={200: OpenApiResponse(description='Revoked agent'), **ADMIN_API_ERRORS},
    ),
)
class PersonalAgentRevokeView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def post(self, request, agent_id):
        user, company, err = require_company_member(request)
        if err:
            return err
        try:
            agent = Agent.objects.select_related('personal_credential').get(
                pk=agent_id,
                company=company,
                created_by=user,
            )
        except Agent.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        if agent.revoked_at is not None:
            return Response({'agent': _agent_summary(agent)})
        now = timezone.now()
        with transaction.atomic():
            agent.revoked_at = now
            agent.save(update_fields=['revoked_at', 'updated_at'])
            cred = getattr(agent, 'personal_credential', None)
            if cred is not None and cred.revoked_at is None:
                cred.revoked_at = now
                cred.save(update_fields=['revoked_at'])
            revoke_all_agent_refresh_sessions(agent)
            invalidate_agent_session_grants(agent)
        return Response({'agent': _agent_summary(agent)})


def _activity_row(row: McpCallLog) -> dict:
    from apps.agents.call_log_outcome import CANONICAL_OUTCOMES, canonical_outcome

    outcome = (row.outcome or '').strip().lower()
    if outcome not in CANONICAL_OUTCOMES:
        outcome = canonical_outcome(row.result, status_code=row.status_code)
    row_out = {
        'timestamp': row.created_at.isoformat(),
        'operation_title': row.operation_title or row.tool or row.path or 'mcp_call',
        'access_kind': row.access_kind or 'unknown',
        'outcome': outcome,
        'resource_label': row.resource_label or row.tool or row.path or '',
        'company_name': row.company_name or '',
        'duration_ms': row.duration_ms,
        'service': row.service,
        'client_ip': row.client_ip,
    }
    if row.approval_id is not None:
        row_out['approval_id'] = str(row.approval_id)
    return row_out


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-personal'],
        operation_id='api_v1_mcp_personal_agent_activity',
        **admin_openapi_fields(
            summary='Activity log for your MCP agent',
            lead='Recent tool calls for an agent you created. Never includes arguments or secrets.',
            side_effects='Read-only.',
        ),
        responses={200: OpenApiResponse(description='Activity rows'), **ADMIN_API_ERRORS},
    ),
)
class PersonalAgentActivityView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, agent_id):
        user, company, err = require_company_member(request)
        if err:
            return err
        try:
            agent = Agent.objects.get(pk=agent_id, company=company, created_by=user)
        except Agent.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        cutoff = _activity_retention_cutoff()
        qs = (
            McpCallLog.objects.filter(agent=agent, company=company, created_at__gte=cutoff)
            .order_by('-created_at')[:200]
        )
        return Response({'agent_id': str(agent.id), 'activity': [_activity_row(r) for r in qs]})
