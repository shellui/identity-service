"""REST admin APIs for MCP agents (company owners; human tokens only)."""

from __future__ import annotations

from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from shellui_django.mcp.decorators import mcp_expose_tool
from shellui_django.mcp.masking import redact_mapping

from apps.authapi.openapi_admin import ADMIN_API_ERRORS, admin_openapi_fields, mcp_extend_schema_kwargs
from apps.authapi.serializers import ShellUIOpenAPISerializer
from apps.agents.display import agent_created_by
from apps.agents.approval_access import pending_approvals_for_user, user_may_manage_approval
from apps.agents.approval_decisions import ApprovalDecisionError, settings_approve, settings_deny
from apps.agents.call_log_outcome import display_outcome_for_read
from apps.agents.models import Agent, McpApprovalRequest, McpCallLog
from apps.agents.permissions import require_approval_actor, require_company_admin


def _approval_row(row: McpApprovalRequest) -> dict:
    return {
        'id': str(row.id),
        'agent_id': str(row.agent_id),
        'agent_name': row.agent.name,
        'service': row.service,
        'action': row.action,
        'tool_name': row.action,
        'target': row.target,
        'arguments_hash': row.arguments_hash,
        'arguments_redacted': redact_mapping(row.arguments_redacted or {}, read_sensitive=False),
        'status': row.status,
        'is_destructive': row.is_destructive,
        'short_action_summary': row.short_action_summary,
        'expires_at': row.expires_at.isoformat(),
    }


def _get_manageable_approval(request, approval_id):
    actor, company, err = require_approval_actor(request, allow_agent_token=False)
    if err:
        return None, None, None, err
    try:
        row = McpApprovalRequest.objects.select_related('agent').get(pk=approval_id, company=company)
    except McpApprovalRequest.DoesNotExist:
        return None, None, None, Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
    if not user_may_manage_approval(actor, row):
        return None, None, None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
    return actor, row, company, None


def _agent_row(agent: Agent) -> dict:
    return {
        'id': str(agent.id),
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
        'created_by': agent_created_by(agent),
    }


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-admin'],
        operation_id='api_v1_mcp_agents_list',
        **admin_openapi_fields(
            summary='List MCP agents',
            lead='Returns MCP agents registered for the company, including pause and revoke state.',
            side_effects='Read-only.',
        ),
        responses={200: OpenApiResponse(description='Agents for the token company'), **ADMIN_API_ERRORS},
    ),
)
class McpAgentListView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        actor, company, err = require_company_admin(request, allow_agent_token=False)
        if err:
            return err
        qs = (
            Agent.objects.filter(company=company)
            .select_related('created_by')
            .order_by('-created_at')[:200]
        )
        return Response({'agents': [_agent_row(a) for a in qs]})


@extend_schema_view(
    post=extend_schema(
        tags=['mcp-admin'],
        operation_id='api_v1_mcp_agents_pause',
        **admin_openapi_fields(
            summary='Pause an MCP agent',
            lead='Pauses an active agent so it cannot call tools until resumed manually.',
            side_effects='Sets `paused_at` on the agent row.',
        ),
        responses={200: OpenApiResponse(description='Updated agent'), **ADMIN_API_ERRORS},
    ),
)
class McpAgentPauseView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def post(self, request, agent_id):
        actor, company, err = require_company_admin(request, allow_agent_token=False)
        if err:
            return err
        try:
            agent = Agent.objects.get(pk=agent_id, company=company)
        except Agent.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        if agent.revoked_at is not None:
            return Response({'error': 'Agent is revoked.'}, status=status.HTTP_409_CONFLICT)
        agent.paused_at = timezone.now()
        agent.save(update_fields=['paused_at', 'updated_at'])
        return Response({'agent': _agent_row(agent)})


@extend_schema_view(
    post=extend_schema(
        tags=['mcp-admin'],
        operation_id='api_v1_mcp_agents_revoke',
        **admin_openapi_fields(
            summary='Revoke an MCP agent',
            lead='Permanently revokes an agent and its refresh sessions.',
            side_effects='Sets `revoked_at`, pauses the agent, and revokes refresh sessions.',
            destructive=True,
        ),
        responses={200: OpenApiResponse(description='Revoked agent'), **ADMIN_API_ERRORS},
    ),
)
class McpAgentRevokeView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def post(self, request, agent_id):
        actor, company, err = require_company_admin(request, allow_agent_token=False)
        if err:
            return err
        try:
            agent = Agent.objects.get(pk=agent_id, company=company)
        except Agent.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        now = timezone.now()
        agent.revoked_at = now
        agent.paused_at = agent.paused_at or now
        agent.save(update_fields=['revoked_at', 'paused_at', 'updated_at'])
        from apps.agents.agent_permissions import invalidate_agent_session_grants
        from apps.agents.models import AgentRefreshSession

        AgentRefreshSession.objects.filter(agent=agent, revoked_at__isnull=True).update(revoked_at=now)
        invalidate_agent_session_grants(agent)
        return Response({'agent': _agent_row(agent)})


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-admin'],
        operation_id='api_v1_mcp_approvals_list',
        **admin_openapi_fields(
            summary='List pending MCP approval requests',
            lead='Returns pending approvals for agents you own or for the whole company when you are an owner.',
            side_effects='Read-only.',
            sensitive=True,
        ),
        responses={200: OpenApiResponse(description='Pending approvals'), **ADMIN_API_ERRORS},
    ),
)
class McpApprovalListView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        actor, company, err = require_approval_actor(request, allow_agent_token=False)
        if err:
            return err
        qs = pending_approvals_for_user(company, actor).select_related('agent')[:100]
        approvals = [_approval_row(row) for row in qs]
        return Response({'approvals': approvals, 'pending_count': len(approvals)})


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-admin'],
        operation_id='api_v1_mcp_approvals_retrieve',
        **admin_openapi_fields(
            summary='Get one MCP approval request',
            lead='Returns one pending or decided approval with redacted arguments.',
            side_effects='Read-only.',
            sensitive=True,
        ),
        responses={200: OpenApiResponse(description='Approval row'), **ADMIN_API_ERRORS},
    ),
)
class McpApprovalDetailView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, approval_id):
        _actor, row, _company, err = _get_manageable_approval(request, approval_id)
        if err:
            return err
        return Response({'approval': _approval_row(row)})


@extend_schema_view(
    post=extend_schema(
        tags=['mcp-admin'],
        operation_id='api_v1_mcp_approvals_approve',
        **admin_openapi_fields(
            summary='Approve an MCP approval request',
            lead='Allows the agent to retry the gated tool call once.',
            side_effects='Marks the approval approved with auditor metadata.',
        ),
        responses={200: OpenApiResponse(description='Approved approval'), **ADMIN_API_ERRORS},
    ),
)
class McpApprovalApproveView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def post(self, request, approval_id):
        actor, row, _company, err = _get_manageable_approval(request, approval_id)
        if err:
            return err
        try:
            result = settings_approve(row, user=actor)
        except ApprovalDecisionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        return Response({'approval': _approval_row(result.row)})


@extend_schema_view(
    post=extend_schema(
        tags=['mcp-admin'],
        operation_id='api_v1_mcp_approvals_reject',
        **admin_openapi_fields(
            summary='Reject an MCP approval request',
            lead='Blocks the gated MCP tool call for this approval id.',
            side_effects='Marks the approval rejected with auditor metadata.',
        ),
        responses={200: OpenApiResponse(description='Rejected approval'), **ADMIN_API_ERRORS},
    ),
)
class McpApprovalRejectView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def post(self, request, approval_id):
        actor, row, _company, err = _get_manageable_approval(request, approval_id)
        if err:
            return err
        try:
            result = settings_deny(row, user=actor)
        except ApprovalDecisionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        return Response({'approval': _approval_row(result.row)})


@extend_schema_view(
    post=extend_schema(
        tags=['mcp-admin'],
        operation_id='api_v1_mcp_approvals_decide',
        **admin_openapi_fields(
            summary='Decide an MCP approval request (Settings)',
            lead='Approve or deny a pending request. Session allow is only available on the client path.',
            side_effects='Updates approval status and writes an audit event.',
        ),
        responses={200: OpenApiResponse(description='Updated approval'), **ADMIN_API_ERRORS},
    ),
)
class McpApprovalDecideView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def post(self, request, approval_id):
        actor, row, _company, err = _get_manageable_approval(request, approval_id)
        if err:
            return err
        body = request.data if isinstance(request.data, dict) else {}
        decision = str(body.get('decision') or '').strip().lower()
        if decision in ('approve', 'allow'):
            handler = settings_approve
        elif decision in ('deny', 'reject'):
            handler = settings_deny
        else:
            return Response({'error': 'decision must be approve or deny.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            result = handler(row, user=actor)
        except ApprovalDecisionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        return Response({'approval': _approval_row(result.row)})


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-admin'],
        operation_id='api_v1_mcp_call_logs_list',
        **admin_openapi_fields(
            summary='List MCP call log entries',
            lead='Returns recent MCP HTTP tool invocations with redacted arguments.',
            side_effects='Read-only.',
            sensitive=True,
        ),
        responses={200: OpenApiResponse(description='Call log rows'), **ADMIN_API_ERRORS},
    ),
)
class McpCallLogListView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        actor, company, err = require_company_admin(request, allow_agent_token=False)
        if err:
            return err
        qs = McpCallLog.objects.filter(company=company).select_related('agent').order_by('-created_at')[:200]
        rows = []
        for row in qs:
            outcome_display = display_outcome_for_read(
                row.outcome,
                result=row.result,
                status_code=row.status_code,
                error_code=row.error_code,
            )
            rows.append(
                {
                    'id': row.id,
                    'agent_id': str(row.agent_id),
                    'agent_name': row.agent.name,
                    'service': row.service,
                    'tool': row.tool,
                    'operation_title': row.operation_title or row.tool or row.path or 'mcp_call',
                    'access_kind': row.access_kind or 'unknown',
                    'outcome': outcome_display,
                    'resource_label': row.resource_label or row.tool or row.path or '',
                    'company_name': row.company_name or '',
                    'approval_id': str(row.approval_id) if row.approval_id is not None else None,
                    'method': row.http_method,
                    'path': row.path,
                    'status_code': row.status_code,
                    'duration_ms': row.duration_ms,
                    'arguments': row.arguments_redacted,
                    'created_at': row.created_at.isoformat(),
                }
            )
        return Response({'call_logs': rows})


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-tools'],
        **mcp_extend_schema_kwargs('api_v1_mcp_services_list'),
        responses={200: OpenApiResponse(description='Connected Shellui MCP services'), **ADMIN_API_ERRORS},
    ),
)
class McpListServicesView(APIView):
    serializer_class = ShellUIOpenAPISerializer

    @mcp_expose_tool(name='list_services', description='Return MCP URLs for connected Shellui services.')
    def get(self, request):
        actor, company, err = require_company_admin(request)
        if err:
            return err
        from apps.agents.services import list_mcp_services

        return Response({'services': list_mcp_services()})
