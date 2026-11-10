"""Browser page for one MCP approval (Approve / Deny).

The link is ``/oauth/mcp/approval/<id>?token=…``. A signed-out visitor signs in
with that company's magic link and OAuth methods, then returns here. Only a
company owner, or the member who created the agent, can decide. Staff accounts
are refused, the same rule as the other MCP pages.
"""

from __future__ import annotations

import re
from datetime import timezone as dt_timezone
from urllib.parse import parse_qs, urlsplit

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.clickjacking import xframe_options_deny
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from apps.agents.approval_access import user_may_manage_approval
from apps.agents.approval_audit import record_approval_expired_once
from apps.agents.approval_decisions import ApprovalDecisionError, settings_approve, settings_deny
from apps.agents.approval_links import (
    APPROVAL_PAGE_PREFIX,
    APPROVAL_RETURN_SESSION_KEY,
    parse_fallback_token,
)
from apps.agents.mcp_copy import copy_for
from apps.agents.mcp_signin import (
    AUTHORIZE_SESSION_KEY,
    COMPANY_SESSION_KEY,
    DEVICE_GRANT_SESSION_KEY,
    page_language,
    protect_page,
)
from apps.agents.models import McpApprovalRequest
from apps.agents.staff import is_mcp_oauth_refused_user

_APPROVAL_PATH_RE = re.compile(
    r'^/oauth/mcp/approval/(?P<approval_id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$'
)


def _fallback_max_age(row: McpApprovalRequest) -> int:
    remaining = (row.expires_at - row.created_at).total_seconds()
    return max(60, int(remaining) + 120)


def _format_expires(row: McpApprovalRequest) -> str:
    stamp = row.expires_at
    aware = stamp if timezone.is_aware(stamp) else timezone.make_aware(stamp, dt_timezone.utc)
    return aware.astimezone(dt_timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def _page_token(request: HttpRequest) -> str:
    return str(request.GET.get('token') or request.POST.get('token') or '').strip()


def _load_row(approval_id: str) -> McpApprovalRequest | None:
    try:
        return McpApprovalRequest.objects.select_related(
            'agent',
            'agent__oauth_client',
            'company',
        ).get(pk=approval_id)
    except (McpApprovalRequest.DoesNotExist, ValueError):
        return None


def _token_matches(row: McpApprovalRequest, token: str) -> bool:
    if not token:
        return False
    return parse_fallback_token(token, max_age_seconds=_fallback_max_age(row)) == str(row.id)


def safe_approval_return_path(raw: object) -> str | None:
    text = str(raw or '')
    if not text or any(ch in text for ch in ('\n', '\r', '\0', '\\', ' ')):
        return None
    if not text.startswith(APPROVAL_PAGE_PREFIX) or text.startswith('//'):
        return None
    parsed = urlsplit(text)
    if parsed.scheme or parsed.netloc or parsed.fragment or not _APPROVAL_PATH_RE.match(parsed.path):
        return None
    token = (parse_qs(parsed.query).get('token') or [''])[0]
    if not token or len(token) > 512:
        return None
    return text


def row_for_approval_path(path: str) -> McpApprovalRequest | None:
    parsed = urlsplit(path)
    match = _APPROVAL_PATH_RE.match(parsed.path or '')
    if match is None:
        return None
    row = _load_row(match.group('approval_id'))
    if row is None:
        return None
    token = (parse_qs(parsed.query).get('token') or [''])[0]
    if not _token_matches(row, token):
        return None
    return row


def remember_approval_return(request: HttpRequest, path: str) -> None:
    request.session[APPROVAL_RETURN_SESSION_KEY] = path
    request.session.pop(AUTHORIZE_SESSION_KEY, None)
    request.session.pop(COMPANY_SESSION_KEY, None)
    request.session.pop(DEVICE_GRANT_SESSION_KEY, None)


def saved_approval_return(request: HttpRequest) -> tuple[str | None, McpApprovalRequest | None]:
    path = safe_approval_return_path(request.session.get(APPROVAL_RETURN_SESSION_KEY))
    if not path:
        return None, None
    row = row_for_approval_path(path)
    if row is None:
        return None, None
    return path, row


def _client_name(row: McpApprovalRequest) -> str:
    agent = row.agent
    if agent is None:
        return ''
    client = getattr(agent, 'oauth_client', None)
    if client is None:
        return ''
    return str(client.client_name or '').strip()


def _agent_name(row: McpApprovalRequest) -> str:
    if row.agent_id is None or row.agent is None:
        return ''
    return str(row.agent.name or '').strip()


def _company_name(row: McpApprovalRequest) -> str:
    if row.company_id is None or row.company is None:
        return ''
    return str(row.company.name or '').strip()


def _arguments_text(row: McpApprovalRequest, copy: dict[str, str]) -> str:
    summary = ' '.join(str(row.short_action_summary or '').split())
    return summary or copy['approval_arguments_empty']


def _terminal_state(row: McpApprovalRequest, now) -> str | None:
    if row.status == McpApprovalRequest.STATUS_APPROVED:
        return 'approved'
    if row.status == McpApprovalRequest.STATUS_EXECUTED:
        return 'approved'
    if row.status == McpApprovalRequest.STATUS_REJECTED:
        return 'denied'
    if row.status == McpApprovalRequest.STATUS_EXPIRED or row.expires_at <= now:
        return 'expired'
    if row.status != McpApprovalRequest.STATUS_PENDING:
        return 'expired'
    return None


def _render(
    request: HttpRequest,
    *,
    copy: dict[str, str],
    state: str,
    title: str,
    body: str = '',
    status: int = 200,
    row: McpApprovalRequest | None = None,
    page_token: str = '',
    show_actions: bool = False,
    show_switch: bool = False,
    show_recap: bool = False,
) -> HttpResponse:
    lang = page_language(request, request.user if getattr(request.user, 'is_authenticated', False) else None)
    ctx = {
        'page_language': lang,
        'copy': copy,
        'state': state,
        'title': title,
        'body': body,
        'show_actions': show_actions,
        'show_switch': show_switch,
        'show_recap': show_recap,
        'page_token': page_token,
    }
    from apps.authapi.identity_session import continue_copy

    ctx['switch_label'] = continue_copy(lang)['use_another']
    if row is not None and show_recap:
        agent_name = _agent_name(row) or copy['approval_agent']
        company_name = _company_name(row)
        ctx.update(
            {
                'company_name': company_name,
                'agent_name': agent_name,
                'client_name': _client_name(row),
                'service_name': row.service,
                'tool_name': row.action,
                'arguments_summary': _arguments_text(row, copy),
                'expires_at_display': _format_expires(row),
                'is_destructive': row.is_destructive,
                'destructive_banner': copy['approval_destructive'].format(company_name=company_name),
                'not_destructive': copy['approval_not_destructive'],
                'safety_line': copy['approval_safety'].format(agent_name=agent_name),
                'lead': copy['approval_lead'].format(
                    agent_name=agent_name,
                    tool_name=row.action,
                    company_name=company_name,
                ),
            }
        )
    response = render(request, 'agents/mcp_approval_fallback.html', ctx, status=status)
    return protect_page(response)


def _unknown(request: HttpRequest) -> HttpResponse:
    copy = copy_for(page_language(request))
    return _render(
        request,
        copy=copy,
        state='unknown',
        title=copy['approval_title_unknown'],
        body=copy['approval_unknown_body'],
        status=404,
    )


def _start_signin(request: HttpRequest, *, path: str) -> HttpResponse:
    remember_approval_return(request, path)
    return HttpResponseRedirect(reverse('mcp-oauth-signin'))


def finish_approval_signin(request: HttpRequest, *, user, company, method: str = '') -> HttpResponse:
    """Finish magic-link or SSO sign-in that started from the approval page."""
    from apps.agents.mcp_signin import is_company_member, render_message
    from apps.authapi.identity_session import MCP_APPROVAL_CONTINUE_KEY, establish_identity_session

    path, row = saved_approval_return(request)
    copy = copy_for(page_language(request, user))
    if path is None or row is None or row.company_id != getattr(company, 'id', None):
        return render_message(request, copy['session_lost'], 400, user=user)
    if is_mcp_oauth_refused_user(user):
        return render_message(request, copy['staff_refused'], 403, user=user)
    if not is_company_member(company, user):
        return render_message(request, copy['not_member'].format(company=company.name), 403, user=user)
    if not establish_identity_session(request, user, company=company, method=method or 'sso'):
        return render_message(request, copy['not_member'].format(company=company.name), 403, user=user)
    remember_approval_return(request, path)
    request.session[MCP_APPROVAL_CONTINUE_KEY] = str(row.id)
    return HttpResponseRedirect(path)


def _decided_copy(copy: dict[str, str], state: str, *, agent_name: str, just_decided: bool) -> tuple[str, str]:
    if state == 'approved':
        title = copy['approval_title_approved']
        body_key = 'approval_approved_body' if just_decided else 'approval_already_approved'
        return title, copy[body_key].format(agent_name=agent_name)
    if state == 'denied':
        title = copy['approval_title_denied']
        body_key = 'approval_denied_body' if just_decided else 'approval_already_denied'
        return title, copy[body_key].format(agent_name=agent_name)
    return copy['approval_title_expired'], copy['approval_expired_body']


@xframe_options_deny
@require_http_methods(['GET', 'POST'])
@csrf_protect
def mcp_approval_fallback(request: HttpRequest, approval_id) -> HttpResponse:
    approval_id = str(approval_id)
    token = _page_token(request)
    row = _load_row(approval_id)
    if row is None or not _token_matches(row, token):
        return _unknown(request)

    lang = page_language(request, request.user if getattr(request.user, 'is_authenticated', False) else None)
    copy = copy_for(lang)
    path = f'{APPROVAL_PAGE_PREFIX}{row.id}?token={token}'
    remember_approval_return(request, path)

    if row.company_id is None or row.agent_id is None:
        return _render(
            request,
            copy=copy,
            state='unavailable',
            title=copy['approval_title_unavailable'],
            body=copy['approval_unavailable_body'],
            row=row,
            show_recap=False,
        )

    now = timezone.now()
    terminal = _terminal_state(row, now)
    agent_name = _agent_name(row)
    if terminal == 'expired' and row.status == McpApprovalRequest.STATUS_PENDING:
        record_approval_expired_once(row)
    if terminal is not None:
        title, body = _decided_copy(copy, terminal, agent_name=agent_name, just_decided=False)
        return _render(
            request,
            copy=copy,
            state=terminal,
            title=title,
            body=body,
            row=row,
            show_recap=True,
            page_token=token,
        )

    from apps.authapi.identity_session import (
        MCP_APPROVAL_CONTINUE_KEY,
        account_email,
        confirmed,
        end_identity_session,
        posted_account_choice,
        render_continue_as,
        user_can_use_company_session,
    )

    choice = posted_account_choice(request)
    if choice == 'switch':
        end_identity_session(request, preserve_flow=True)
        return _start_signin(request, path=path)

    user = request.user
    signed_in = bool(getattr(user, 'is_authenticated', False)) and user_can_use_company_session(user, row.company)
    if not signed_in:
        return _start_signin(request, path=path)

    if is_mcp_oauth_refused_user(user):
        return _render(
            request,
            copy=copy,
            state='staff',
            title=copy['error_title'],
            body=copy['staff_refused'],
            status=403,
            show_switch=True,
            page_token=token,
        )

    if not user_may_manage_approval(user, row):
        return _render(
            request,
            copy=copy,
            state='wrong_account',
            title=copy['approval_title_wrong'],
            body=copy['approval_wrong_body'].format(company_name=_company_name(row)),
            status=403,
            show_switch=True,
            page_token=token,
        )

    if choice == 'continue':
        request.session[MCP_APPROVAL_CONTINUE_KEY] = str(row.id)
    elif not confirmed(request, MCP_APPROVAL_CONTINUE_KEY, str(row.id)):
        return render_continue_as(
            request,
            email=account_email(user),
            lead=copy['approval_lead'].format(
                agent_name=agent_name,
                tool_name=row.action,
                company_name=_company_name(row),
            ),
            hidden_fields={'token': token},
        )

    if request.method == 'POST':
        decision = str(request.POST.get('decision') or '').strip().lower()
        handler = {'approve': settings_approve, 'deny': settings_deny}.get(decision)
        if handler is not None:
            try:
                handler(row, user=user)
                row.refresh_from_db()
                state = 'approved' if decision == 'approve' else 'denied'
                title, body = _decided_copy(copy, state, agent_name=agent_name, just_decided=True)
                return _render(
                    request,
                    copy=copy,
                    state=state,
                    title=title,
                    body=body,
                    row=row,
                    show_recap=True,
                    page_token=token,
                )
            except ApprovalDecisionError:
                row.refresh_from_db()
                raced = _terminal_state(row, timezone.now()) or 'expired'
                if raced == 'expired' and row.status == McpApprovalRequest.STATUS_PENDING:
                    record_approval_expired_once(row)
                title, body = _decided_copy(copy, raced, agent_name=agent_name, just_decided=False)
                return _render(
                    request,
                    copy=copy,
                    state=raced,
                    title=title,
                    body=body,
                    row=row,
                    show_recap=True,
                    page_token=token,
                )

    return _render(
        request,
        copy=copy,
        state='pending',
        title=copy['approval_title_pending'],
        row=row,
        show_actions=True,
        show_recap=True,
        page_token=token,
    )
