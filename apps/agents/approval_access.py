"""Who may list or decide MCP approval requests for a company."""

from __future__ import annotations

from django.db.models import QuerySet

from apps.agents.models import Agent, McpApprovalRequest
from apps.authapi.views import _is_user_company_owner
from apps.companies.models import Company


def user_may_manage_agent(user, agent: Agent) -> bool:
    company = agent.company
    if _is_user_company_owner(user, company):
        return True
    return agent.created_by_id is not None and agent.created_by_id == user.pk


def user_may_manage_approval(user, row: McpApprovalRequest) -> bool:
    return user_may_manage_agent(user, row.agent)


def pending_approvals_for_user(company: Company, user) -> QuerySet[McpApprovalRequest]:
    from django.utils import timezone

    qs = McpApprovalRequest.objects.filter(
        company=company,
        status=McpApprovalRequest.STATUS_PENDING,
        expires_at__gt=timezone.now(),
    ).select_related('agent', 'agent__created_by')
    if _is_user_company_owner(user, company):
        return qs
    return qs.filter(agent__created_by=user)
