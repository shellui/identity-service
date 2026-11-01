from django.urls import path

from apps.agents import admin_views, internal_views

urlpatterns = [
    path('agents', admin_views.McpAgentListView.as_view(), name='mcp-agents-list'),
    path('agents/<uuid:agent_id>/pause', admin_views.McpAgentPauseView.as_view(), name='mcp-agent-pause'),
    path('agents/<uuid:agent_id>/revoke', admin_views.McpAgentRevokeView.as_view(), name='mcp-agent-revoke'),
    path('approvals', admin_views.McpApprovalListView.as_view(), name='mcp-approvals-list'),
    path('approvals/<uuid:approval_id>', admin_views.McpApprovalDetailView.as_view(), name='mcp-approval-detail'),
    path('approvals/<uuid:approval_id>/approve', admin_views.McpApprovalApproveView.as_view(), name='mcp-approval-approve'),
    path('approvals/<uuid:approval_id>/reject', admin_views.McpApprovalRejectView.as_view(), name='mcp-approval-reject'),
    path('call-logs', admin_views.McpCallLogListView.as_view(), name='mcp-call-logs'),
    path('services', admin_views.McpListServicesView.as_view(), name='mcp-services-list'),
    path('internal/mcp-revocations', internal_views.McpRevocationListView.as_view(), name='mcp-revocations'),
    path('internal/mcp-approval-requests', internal_views.McpInternalApprovalCreateView.as_view(), name='mcp-internal-approval'),
    path('internal/mcp-approval-state', internal_views.McpInternalApprovalStateView.as_view(), name='mcp-internal-approval-state'),
    path('internal/mcp-approval-consume', internal_views.McpInternalApprovalConsumeView.as_view(), name='mcp-internal-approval-consume'),
    path('internal/mcp-call-logs', internal_views.McpInternalCallLogView.as_view(), name='mcp-internal-call-log'),
]
