"""Browser fallback page for MCP approval (Approve/Deny only)."""

from __future__ import annotations

import math

from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.clickjacking import xframe_options_deny
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from apps.agents.approval_access import user_may_manage_approval
from apps.agents.approval_audit import record_approval_expired_once
from apps.agents.approval_decisions import ApprovalDecisionError, settings_approve, settings_deny
from apps.agents.approval_links import parse_fallback_token
from apps.agents.models import McpApprovalRequest
from apps.agents.mcp_signin import CSP_HEADER, MCP_REFERRER_POLICY
from apps.federation.models import ProvisionedCompany

COPY = {
    'title_pending': 'Approve this action?',
    'title_approved': 'Approved',
    'title_denied': 'Denied',
    'title_expired': 'This approval is no longer valid',
    'primary_approve': 'Approve',
    'secondary_deny': 'Deny',
    'footer': 'Review pending approvals in Settings → MCP / AI agents',
    'after_approve_body': 'You can return to {agent_name}. This window can be closed.',
    'after_deny_body': 'Nothing was changed. You can return to {agent_name}.',
    'expired_body': 'It expired or was already used. Ask the agent to send a new request.',
    'wrong_account': 'Sign in with the account that owns this connection, then open the link again.',
    'destructive_banner': 'This can change data in {company_name}.',
    'safety': 'Only continue if you started this from {agent_name}.',
}


def _fallback_max_age(row: McpApprovalRequest) -> int:
    remaining = (row.expires_at - row.created_at).total_seconds()
    return max(60, int(remaining) + 120)


def _expires_in_minutes(row: McpApprovalRequest) -> int:
    delta = row.expires_at - timezone.now()
    minutes = delta.total_seconds() / 60.0
    return max(1, int(math.ceil(minutes)))


def _protect(response: HttpResponse) -> HttpResponse:
    response['X-Frame-Options'] = 'DENY'
    response['Content-Security-Policy'] = CSP_HEADER
    response['Referrer-Policy'] = MCP_REFERRER_POLICY
    return response


def _fallback_agent_company_labels(row: McpApprovalRequest) -> tuple[str, str]:
    if row.agent_id is not None:
        agent_name = row.agent.name
    else:
        agent_name = 'Global control plane'
    if row.company_id is not None:
        company_name = row.company.name
    elif row.global_company_id is not None:
        pc = (
            ProvisionedCompany.objects.filter(global_company_id=str(row.global_company_id))
            .select_related('company')
            .first()
        )
        company_name = pc.company.name if pc is not None else ''
    else:
        company_name = ''
    return agent_name, company_name


def _render_state(request: HttpRequest, *, row: McpApprovalRequest, state: str) -> HttpResponse:
    agent_name, company_name = _fallback_agent_company_labels(row)
    tool_name = row.action
    ctx = {
        'copy': COPY,
        'state': state,
        'agent_name': agent_name,
        'company_name': company_name,
        'tool_name': tool_name,
        'detail': (row.short_action_summary or '').strip(),
        'expires_in_minutes': _expires_in_minutes(row),
        'is_destructive': row.is_destructive,
        'destructive_banner': COPY['destructive_banner'].format(company_name=company_name),
        'safety_line': COPY['safety'].format(agent_name=agent_name),
        'page_token': str(request.GET.get('token') or request.POST.get('token') or ''),
    }
    if state == 'approved':
        ctx['title'] = COPY['title_approved']
        ctx['body'] = COPY['after_approve_body'].format(agent_name=agent_name)
    elif state == 'denied':
        ctx['title'] = COPY['title_denied']
        ctx['body'] = COPY['after_deny_body'].format(agent_name=agent_name)
    elif state == 'expired':
        ctx['title'] = COPY['title_expired']
        ctx['body'] = COPY['expired_body']
    elif state == 'wrong_account':
        ctx['title'] = COPY['title_pending']
        ctx['body'] = COPY['wrong_account']
    else:
        ctx['title'] = COPY['title_pending']
        on_label = company_name if company_name else 'your organization'
        ctx['lead'] = f'{agent_name} wants to run {tool_name} on {on_label}.'
    response = render(request, 'agents/mcp_approval_fallback.html', ctx)
    return _protect(response)


def _row_from_request(request: HttpRequest, approval_id: str) -> McpApprovalRequest | None:
    token = str(request.GET.get('token') or request.POST.get('token') or '').strip()
    if not token:
        return None
    row = get_object_or_404(McpApprovalRequest.objects.select_related('agent', 'company'), pk=approval_id)
    parsed_id = parse_fallback_token(token, max_age_seconds=_fallback_max_age(row))
    if parsed_id != str(row.id):
        return None
    return row


@xframe_options_deny
@require_http_methods(['GET', 'POST'])
@csrf_protect
def mcp_approval_fallback(request: HttpRequest, approval_id: str) -> HttpResponse:
    row = _row_from_request(request, approval_id)
    if row is None:
        return _protect(HttpResponse('Not found.', status=404))

    now = timezone.now()
    pending = row.status == McpApprovalRequest.STATUS_PENDING and row.expires_at > now
    if not pending:
        record_approval_expired_once(row)
        return _render_state(request, row=row, state='expired')

    if not request.user.is_authenticated:
        login_url = reverse('root')
        return redirect(f'{login_url}?next={request.get_full_path()}')

    if not user_may_manage_approval(request.user, row):
        return _render_state(request, row=row, state='wrong_account')

    if request.method == 'POST':
        decision = str(request.POST.get('decision') or '').strip().lower()
        try:
            if decision == 'approve':
                settings_approve(row, user=request.user)
                row.refresh_from_db()
                return _render_state(request, row=row, state='approved')
            if decision == 'deny':
                settings_deny(row, user=request.user)
                row.refresh_from_db()
                return _render_state(request, row=row, state='denied')
        except ApprovalDecisionError:
            record_approval_expired_once(row)
            return _render_state(request, row=row, state='expired')

    return _render_state(request, row=row, state='pending')
