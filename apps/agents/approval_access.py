"""Who may list or decide MCP approval requests for a company."""

from __future__ import annotations

import uuid

from django.db.models import Q, QuerySet

from apps.agents.models import Agent, McpApprovalRequest
from apps.authapi.views import _is_user_company_owner
from apps.companies.models import Company
from apps.federation.models import ProvisionedCompany


def user_may_manage_agent(user, agent: Agent) -> bool:
    company = agent.company
    if _is_user_company_owner(user, company):
        return True
    return agent.created_by_id is not None and agent.created_by_id == user.pk


def user_may_manage_approval(user, row: McpApprovalRequest) -> bool:
    """Regional rows: owner or agent creator. Global rows (no regional ``Agent`` yet): company owners only."""
    if row.agent_id is None:
        if row.global_company_id is None:
            return False
        pc = ProvisionedCompany.objects.filter(global_company_id=str(row.global_company_id)).select_related('company').first()
        if pc is None:
            return False
        return _is_user_company_owner(user, pc.company)
    return user_may_manage_agent(user, row.agent)


def pending_approvals_for_user(company: Company, user) -> QuerySet[McpApprovalRequest]:
    from django.utils import timezone

    now = timezone.now()
    gc_uuids: list[uuid.UUID] = []
    for raw in ProvisionedCompany.objects.filter(company=company).values_list('global_company_id', flat=True):
        try:
            gc_uuids.append(uuid.UUID(str(raw)))
        except (ValueError, TypeError, AttributeError):
            continue

    base = McpApprovalRequest.objects.filter(
        status=McpApprovalRequest.STATUS_PENDING,
        expires_at__gt=now,
    ).select_related('agent', 'agent__created_by')
    if _is_user_company_owner(user, company):
        if gc_uuids:
            return base.filter(
                Q(company=company)
                | Q(agent_id__isnull=True, company_id__isnull=True, global_company_id__in=gc_uuids)
            )
        return base.filter(company=company)
    return base.filter(company=company, agent__created_by=user)
