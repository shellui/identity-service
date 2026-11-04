from django.urls import path

from apps.agents import admin_views, downstream_internal, internal_views, personal_views

urlpatterns = [
    path('personal/status', personal_views.PersonalMcpStatusView.as_view(), name='mcp-personal-status'),
    path('personal/agents', personal_views.PersonalAgentListView.as_view(), name='mcp-personal-agents'),
    path('personal/agents/create', personal_views.PersonalAgentTokenCreateView.as_view(), name='mcp-personal-agents-create'),
    path(
        'personal/agents/<uuid:agent_id>/revoke',
        personal_views.PersonalAgentRevokeView.as_view(),
        name='mcp-personal-agent-revoke',
    ),
    path(
        'personal/agents/<uuid:agent_id>/activity',
        personal_views.PersonalAgentActivityView.as_view(),
        name='mcp-personal-agent-activity',
    ),
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
    path(
        'internal/mcp-downstream-access-token',
        downstream_internal.McpDownstreamAccessTokenView.as_view(),
        name='mcp-downstream-access-token',
    ),
]
