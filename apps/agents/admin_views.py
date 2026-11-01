"""REST admin APIs for MCP agents (company owners and staff)."""

from __future__ import annotations

from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from shellui_mcp.decorators import mcp_expose_tool

from apps.agents.models import Agent, McpApprovalRequest, McpCallLog
from apps.agents.permissions import require_company_admin


def _agent_row(agent: Agent) -> dict:
    return {
        'id': str(agent.id),
        'name': agent.name,
        'access_mode': agent.access_mode,
        'read_level': agent.read_level,
        'allow_destructive_without_asking': agent.allow_destructive_without_asking,
        'services_allowed': agent.services_allowed,
        'project_scope': agent.project_scope,
        'expires_at': agent.expires_at.isoformat() if agent.expires_at else None,
        'paused_at': agent.paused_at.isoformat() if agent.paused_at else None,
        'revoked_at': agent.revoked_at.isoformat() if agent.revoked_at else None,
        'is_active': agent.is_active,
        'created_at': agent.created_at.isoformat(),
    }


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-tools'],
        summary='List MCP agents',
        responses={200: OpenApiResponse(description='Agents for the token company')},
    ),
)
class McpAgentListView(APIView):
    @mcp_expose_tool(name='list_mcp_agents', description='List MCP agents for the company.')
    def get(self, request):
        actor, company, err = require_company_admin(request)
        if err:
            return err
        qs = Agent.objects.filter(company=company).order_by('-created_at')[:200]
        return Response({'agents': [_agent_row(a) for a in qs]})


@extend_schema_view(
    post=extend_schema(
        tags=['mcp-tools'],
        summary='Pause an MCP agent',
    ),
)
class McpAgentPauseView(APIView):
    @mcp_expose_tool(name='pause_mcp_agent')
    def post(self, request, agent_id):
        actor, company, err = require_company_admin(request)
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
        tags=['mcp-tools'],
        summary='Revoke an MCP agent',
    ),
)
class McpAgentRevokeView(APIView):
    @mcp_expose_tool(name='revoke_mcp_agent')
    def post(self, request, agent_id):
        actor, company, err = require_company_admin(request)
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
        from apps.agents.models import AgentRefreshSession

        AgentRefreshSession.objects.filter(agent=agent, revoked_at__isnull=True).update(revoked_at=now)
        return Response({'agent': _agent_row(agent)})


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-tools'],
        summary='List pending MCP approval requests',
    ),
)
class McpApprovalListView(APIView):
    @mcp_expose_tool(name='list_mcp_approvals')
    def get(self, request):
        actor, company, err = require_company_admin(request)
        if err:
            return err
        now = timezone.now()
        qs = McpApprovalRequest.objects.filter(
            company=company,
            status=McpApprovalRequest.STATUS_PENDING,
            expires_at__gt=now,
        ).select_related('agent')[:100]
        rows = []
        for row in qs:
            rows.append(
                {
                    'id': str(row.id),
                    'agent_id': str(row.agent_id),
                    'agent_name': row.agent.name,
                    'service': row.service,
                    'action': row.action,
                    'arguments_hash': row.arguments_hash,
                    'expires_at': row.expires_at.isoformat(),
                }
            )
        return Response({'approvals': rows})


@extend_schema_view(
    post=extend_schema(
        tags=['mcp-tools'],
        summary='Approve an MCP approval request',
    ),
)
class McpApprovalApproveView(APIView):
    @mcp_expose_tool(name='approve_mcp_request')
    def post(self, request, approval_id):
        actor, company, err = require_company_admin(request)
        if err:
            return err
        try:
            row = McpApprovalRequest.objects.select_related('agent').get(pk=approval_id, company=company)
        except McpApprovalRequest.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        if row.status != McpApprovalRequest.STATUS_PENDING or row.expires_at <= timezone.now():
            return Response({'error': 'Approval is not pending.'}, status=status.HTTP_409_CONFLICT)
        row.status = McpApprovalRequest.STATUS_APPROVED
        row.decided_at = timezone.now()
        row.decided_by = actor
        row.save(update_fields=['status', 'decided_at', 'decided_by'])
        return Response({'id': str(row.id), 'status': row.status})


@extend_schema_view(
    post=extend_schema(
        tags=['mcp-tools'],
        summary='Reject an MCP approval request',
    ),
)
class McpApprovalRejectView(APIView):
    @mcp_expose_tool(name='reject_mcp_request')
    def post(self, request, approval_id):
        actor, company, err = require_company_admin(request)
        if err:
            return err
        try:
            row = McpApprovalRequest.objects.get(pk=approval_id, company=company)
        except McpApprovalRequest.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        if row.status != McpApprovalRequest.STATUS_PENDING:
            return Response({'error': 'Approval is not pending.'}, status=status.HTTP_409_CONFLICT)
        row.status = McpApprovalRequest.STATUS_REJECTED
        row.decided_at = timezone.now()
        row.decided_by = actor
        row.save(update_fields=['status', 'decided_at', 'decided_by'])
        return Response({'id': str(row.id), 'status': row.status})


@extend_schema_view(
    get=extend_schema(
        tags=['mcp-tools'],
        summary='List MCP call log entries',
    ),
)
class McpCallLogListView(APIView):
    @mcp_expose_tool(name='list_mcp_call_logs')
    def get(self, request):
        actor, company, err = require_company_admin(request)
        if err:
            return err
        qs = McpCallLog.objects.filter(company=company).select_related('agent').order_by('-created_at')[:200]
        rows = []
        for row in qs:
            rows.append(
                {
                    'id': row.id,
                    'agent_id': str(row.agent_id),
                    'agent_name': row.agent.name,
                    'service': row.service,
                    'tool': row.tool,
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
        summary='List Shellui MCP service URLs',
    ),
)
class McpListServicesView(APIView):
    @mcp_expose_tool(name='list_services', description='Return MCP URLs for connected Shellui services.')
    def get(self, request):
        actor, company, err = require_company_admin(request)
        if err:
            return err
        from apps.agents.services import list_mcp_services

        return Response({'services': list_mcp_services()})
