"""Identity-hosted sign-in and consent for MCP OAuth clients (ChatGPT, Claude, Grok, MCP Inspector).

The company comes from the per-company resource (``{AI_SERVICE_URL}/c/<company_id>/mcp``).
Identity renders every page itself. The page offers only the sign-in methods that company
has turned on, through identity's existing magic link and OAuth/SSO flows. Those flows land
on :func:`signin_complete_url`, which starts the identity session and returns to the saved
authorize path. Nothing here redirects to an address that was not registered by the client.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit

from django.conf import settings
from django.db import transaction
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.clickjacking import xframe_options_deny
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from apps.agents.mcp_copy import copy_for, error_message
from apps.agents.mcp_resources import resolve_mcp_resource, resource_company_id
from apps.agents.models import McpOAuthClient
from apps.agents.oauth_redirect import redirect_uri_host, validate_mcp_redirect_uri
from apps.agents.staff import is_mcp_oauth_refused_user
from apps.authapi.client_pkce import PkceError, parse_client_pkce
from apps.companies.models import Company

logger = logging.getLogger(__name__)

AUTHORIZE_SESSION_KEY = 'mcp_oauth_authorize_path'
COMPANY_SESSION_KEY = 'mcp_oauth_company_id'
DEVICE_GRANT_SESSION_KEY = 'mcp_device_grant_id'
SIGNIN_COMPLETE_PATH = '/oauth/mcp/signin/complete'
AUTHORIZE_PATH = '/oauth/mcp/authorize'
SESSION_BACKEND = 'django.contrib.auth.backends.ModelBackend'
CSP_HEADER = "frame-ancestors 'none'"
# Cross-origin navigations send no Referer; same-origin form POSTs keep a valid Origin for CSRF.
MCP_REFERRER_POLICY = 'same-origin'


@dataclass
class AuthorizeRequest:
    client: McpOAuthClient
    redirect_uri: str
    redirect_host: str
    resource: str
    service_id: str
    company: Company | None
    company_id: int
    state: str
    challenge: str


class AuthorizeError(Exception):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


def _issuer() -> str:
    return str(getattr(settings, 'JWT_ISSUER', '') or '').strip().rstrip('/')


def identity_login_host(request: HttpRequest) -> str:
    issuer = _issuer()
    host = urlsplit(issuer).netloc if issuer else ''
    if not host:
        host = request.get_host()
    return host.split('@')[-1]


def mcp_cancel_return_url(parsed: AuthorizeRequest) -> str:
    params = {'error': 'access_denied'}
    if parsed.state:
        params['state'] = parsed.state
    sep = '&' if '?' in parsed.redirect_uri else '?'
    return f'{parsed.redirect_uri}{sep}{urlencode(params)}'


def mcp_signin_page_strings(
    request: HttpRequest,
    *,
    copy: dict[str, str],
    client_name: str,
    login_host: str,
) -> dict[str, str]:
    company_name = copy['signin_company_name']
    return {
        'lead': copy['why_signin'].format(client_name=client_name, company_name=company_name),
        'redirect_notice': copy['redirect_notice'].format(login_host=login_host),
        'phishing': copy['phishing'].format(client_name=client_name),
    }


def signin_complete_url(request: HttpRequest | None = None) -> str:
    base = _issuer()
    if not base and request is not None:
        base = request.build_absolute_uri('/').rstrip('/')
    return f'{base}{SIGNIN_COMPLETE_PATH}' if base else ''


def is_mcp_signin_redirect(url: str | None) -> bool:
    """True when a sign-in flow's ``redirect_to`` is the MCP sign-in landing on this identity."""
    target = str(url or '').strip()
    expected = signin_complete_url()
    return bool(target and expected and target == expected)


def build_authorize_path(parsed: AuthorizeRequest, *, saas_offered: bool = False) -> str:
    params = {
        'response_type': 'code',
        'client_id': parsed.client.client_id,
        'redirect_uri': parsed.redirect_uri,
        'resource': parsed.resource,
        'code_challenge': parsed.challenge,
        'code_challenge_method': 'S256',
    }
    if parsed.state:
        params['state'] = parsed.state
    if saas_offered:
        params['saas_offered'] = '1'
    return f'{AUTHORIZE_PATH}?{urlencode(params)}'


def saas_offered_in_params(params) -> bool:
    return _first(params, 'saas_offered') in {'1', 'true', 'yes'}


def safe_authorize_path(raw: str | None) -> str | None:
    """Only a same-origin relative path to the MCP authorize endpoint is ever stored or followed."""
    s = str(raw or '')
    if not s or len(s) > 4096:
        return None
    if any(ch in s for ch in ('\n', '\r', '\0', '\\')):
        return None
    if not s.startswith(AUTHORIZE_PATH + '?') or s.startswith('//'):
        return None
    parsed = urlsplit(s)
    if parsed.scheme or parsed.netloc or parsed.fragment or parsed.path != AUTHORIZE_PATH:
        return None
    return s


def page_language(request: HttpRequest, user=None) -> str:
    from apps.authapi.magic_link_views import _page_language

    return _page_language(request, user)


def _first(params, key: str) -> str:
    value = params.get(key)
    if isinstance(value, list):
        value = value[0] if value else ''
    return str(value or '').strip()


def parse_authorize_request(params) -> AuthorizeRequest:
    """Validate an authorize request. Raises :class:`AuthorizeError`; never redirects."""
    if (_first(params, 'response_type') or 'code') != 'code':
        raise AuthorizeError('invalid_request')
    client_id = _first(params, 'client_id')
    if not client_id:
        raise AuthorizeError('invalid_client')
    client = McpOAuthClient.objects.filter(client_id=client_id).first()
    if client is None:
        raise AuthorizeError('invalid_client')
    redirect_uri = _first(params, 'redirect_uri')
    checked, err = validate_mcp_redirect_uri(None, redirect_uri)
    if err or not checked or checked not in (client.redirect_uris or []):
        raise AuthorizeError('invalid_redirect_uri')
    resource_raw = _first(params, 'resource')
    if not resource_raw:
        raise AuthorizeError('company_required')
    resource, service_id = resolve_mcp_resource(resource_raw)
    if not resource:
        raise AuthorizeError('invalid_resource')
    company_id = resource_company_id(resource)
    if company_id is None:
        raise AuthorizeError('company_required')
    # An unknown company is not an error here. Before sign-in it must look exactly like a
    # known one (no id-to-company oracle); authorize answers 404 only after sign-in.
    company = Company.objects.filter(pk=company_id, deletion_requested_at__isnull=True).first()
    try:
        challenge = parse_client_pkce(
            _first(params, 'code_challenge') or None,
            _first(params, 'code_challenge_method') or None,
            required=True,
        )
    except PkceError:
        raise AuthorizeError('invalid_request') from None
    return AuthorizeRequest(
        client=client,
        redirect_uri=checked,
        redirect_host=redirect_uri_host(checked),
        resource=resource,
        service_id=service_id,
        company=company,
        company_id=company_id,
        state=_first(params, 'state'),
        challenge=challenge,
    )


def plain_response(response):
    """DRF rate-limit responses cannot render outside an APIView; return a JsonResponse."""
    if response is None:
        return None
    from django.http import JsonResponse

    data = getattr(response, 'data', None)
    out = JsonResponse(data if isinstance(data, dict) else {'error': 'rate_limited'}, status=response.status_code)
    retry = response.get('Retry-After') if hasattr(response, 'get') else None
    if retry:
        out['Retry-After'] = retry
    return out


def protect_page(response: HttpResponse) -> HttpResponse:
    response['X-Frame-Options'] = 'DENY'
    response['Content-Security-Policy'] = CSP_HEADER
    response['Cache-Control'] = 'no-store'
    response['Referrer-Policy'] = MCP_REFERRER_POLICY
    return response


def render_error(request: HttpRequest, code: str, status: int = 400, *, user=None) -> HttpResponse:
    lang = page_language(request, user)
    copy = copy_for(lang)
    response = render(
        request,
        'agents/mcp_error.html',
        {
            'page_language': lang,
            'copy': copy,
            'title': copy['error_title'],
            'message': error_message(lang, code),
            'error_code': code,
        },
        status=status,
    )
    return protect_page(response)


def render_message(request: HttpRequest, message: str, status: int = 200, *, user=None) -> HttpResponse:
    lang = page_language(request, user)
    copy = copy_for(lang)
    response = render(
        request,
        'agents/mcp_error.html',
        {'page_language': lang, 'copy': copy, 'title': copy['error_title'], 'message': message, 'error_code': ''},
        status=status,
    )
    return protect_page(response)


def is_company_member(company: Company, user) -> bool:
    if company.owners.filter(pk=user.pk).exists():
        return True
    return company.memberships.filter(user=user, is_enabled=True).exists()


def remember_authorize(request: HttpRequest, path: str, company_id: int) -> None:
    request.session[AUTHORIZE_SESSION_KEY] = path
    request.session[COMPANY_SESSION_KEY] = int(company_id)
    request.session.pop(DEVICE_GRANT_SESSION_KEY, None)


def remember_device_grant(request: HttpRequest, grant_id: str) -> None:
    """Bind this browser to a device grant. The id is not a secret; codes stay hashed in the database."""
    request.session[DEVICE_GRANT_SESSION_KEY] = str(grant_id)
    request.session.pop(AUTHORIZE_SESSION_KEY, None)
    request.session.pop(COMPANY_SESSION_KEY, None)


def clear_device_grant(request: HttpRequest) -> None:
    """Drop the browser↔device-grant binding (after a finished grant or a new user_code)."""
    request.session.pop(DEVICE_GRANT_SESSION_KEY, None)


def _saved_authorize(request: HttpRequest) -> tuple[str | None, AuthorizeRequest | None]:
    path = safe_authorize_path(request.session.get(AUTHORIZE_SESSION_KEY))
    if not path:
        return None, None
    try:
        parsed = parse_authorize_request(parse_qs(urlsplit(path).query))
    except AuthorizeError:
        return None, None
    if parsed.company_id != request.session.get(COMPANY_SESSION_KEY):
        return None, None
    return path, parsed


def finish_mcp_signin(request: HttpRequest, *, user, company: Company, method: str = '') -> HttpResponse:
    """Called by the magic link and OAuth/SSO flows when ``redirect_to`` is the MCP landing."""
    path, parsed = _saved_authorize(request)
    if not path or parsed is None:
        from apps.agents.oauth_device import finish_device_signin

        return finish_device_signin(request, user=user, company=company, method=method)
    copy = copy_for(page_language(request, user))
    if parsed.company is None or parsed.company.id != company.id:
        return render_message(request, copy['session_lost'], 400, user=user)
    if is_mcp_oauth_refused_user(user):
        return render_message(request, copy['staff_refused'], 403, user=user)
    if not is_company_member(company, user):
        return render_message(request, copy['not_member'].format(company=company.name), 403, user=user)
    from apps.authapi.identity_session import MCP_AUTHORIZE_CONTINUE_KEY, establish_identity_session

    if not establish_identity_session(request, user, company=company, method=method or 'sso'):
        return render_message(request, copy['not_member'].format(company=company.name), 403, user=user)
    # login() rotates the session; store the path again on the new session.
    remember_authorize(request, path, company.id)
    request.session[MCP_AUTHORIZE_CONTINUE_KEY] = f'{parsed.client.client_id}:{parsed.company_id}'
    return HttpResponseRedirect(path)


def _send_magic_link(
    request: HttpRequest,
    *,
    company: Company,
    email: str,
    lang: str,
    rate_limit: bool = True,
) -> HttpResponse | None:
    """Reuse identity's magic link rules. Returns a response only when rate limited."""
    from apps.authapi import magic_link_views as mlv
    from apps.authapi.magic_link import create_magic_link_token, is_staff_account, staff_account_for_email

    if rate_limit:
        limited = mlv._magic_link_rate_limits(request, company_id=company.id, email=email)
        if limited is not None:
            return limited
    existing = mlv.User.objects.filter(email__iexact=email).first()
    if mlv.is_login_blocked_by_revoked_invitation(company, email, existing):
        return None
    staff_user = existing if is_staff_account(existing) else staff_account_for_email(email)
    if staff_user is not None:
        # Same answer as for any address. Staff get the built-in notice, never a link.
        logger.info('mcp_signin_magic_link_staff_refused company_id=%s', company.pk)
        return None
    with transaction.atomic():
        row, raw_token = create_magic_link_token(
            company=company,
            email=email,
            redirect_to=signin_complete_url(request),
            user=existing,
        )
        mlv._deliver_or_error_response(
            lambda: mlv.deliver_magic_link_email(
                row=row,
                company=company,
                user=existing,
                language=lang,
                raw_token=raw_token,
                fallback_base_url=request.build_absolute_uri('/'),
            ),
            company=company,
            request_id=row.pk,
        )
    return None


@xframe_options_deny
@csrf_protect
@require_http_methods(['GET', 'POST'])
def mcp_signin(request: HttpRequest) -> HttpResponse:
    from apps.authapi.magic_link import magic_link_enabled_for_company
    from apps.authapi.throttling import check_rate_limit

    # Per IP, before anything else.
    limited = plain_response(check_rate_limit(request, scope='mcp_signin'))
    if limited:
        return limited
    path, parsed = _saved_authorize(request)
    from apps.agents.oauth_device import device_grant_for_signin

    device_grant, device_error = device_grant_for_signin(request)
    if parsed is None and device_grant is None:
        if device_error and not path:
            return render_error(request, device_error, 400)
        return render_error(request, 'invalid_request', 400)
    # Nothing on this page depends on the company name. Device grants already bound a company
    # from the user code, and the email step uses that company's sign-in methods only.
    company = parsed.company if parsed is not None else device_grant.company
    lang = page_language(request)
    copy = copy_for(lang)
    from apps.authapi.identity_session import (
        MCP_AUTHORIZE_CONTINUE_KEY,
        MCP_DEVICE_CONTINUE_KEY,
        account_email,
        end_identity_session,
        posted_account_choice,
        render_continue_as,
        user_can_use_company_session,
    )

    if request.user.is_authenticated and is_mcp_oauth_refused_user(request.user):
        if posted_account_choice(request) == 'switch':
            end_identity_session(request, preserve_flow=True)
        else:
            return render_message(request, copy['staff_refused'], 403, user=request.user)
    eligible = (
        request.user.is_authenticated
        and company is not None
        and user_can_use_company_session(request.user, company)
    )
    choice = posted_account_choice(request)
    if choice == 'switch':
        end_identity_session(request, preserve_flow=True)
        eligible = False
    elif choice == 'continue' and eligible:
        if parsed is not None and path:
            request.session[MCP_AUTHORIZE_CONTINUE_KEY] = f'{parsed.client.client_id}:{parsed.company_id}'
            return HttpResponseRedirect(path)
        if device_grant is not None:
            request.session[MCP_DEVICE_CONTINUE_KEY] = str(device_grant.id)
            return HttpResponseRedirect(reverse('mcp-oauth-device'))
        return render_error(request, 'invalid_request', 400)
    elif request.method == 'GET' and eligible:
        if parsed is not None:
            client_name = parsed.client.client_name or parsed.client.client_id
        else:
            client_name = device_grant.client.client_name or device_grant.client.client_id
        return render_continue_as(
            request,
            email=account_email(request.user),
            lead=copy['why_signin'].format(client_name=client_name, company_name=copy['signin_company_name']),
        )
    sent = False
    if request.method == 'POST' and choice != 'switch':
        email = str(request.POST.get('email') or '').strip().lower()
        if not email or '@' not in email or len(email) > 254:
            return render_error(request, 'invalid_request', 400)
        if company is not None:
            from apps.authapi import magic_link_views as mlv

            limited = plain_response(
                mlv._magic_link_rate_limits(request, company_id=company.id, email=email)
            )
            if limited is not None:
                return limited
            from apps.agents.mcp_home_realm import home_realm_signin_redirect

            realm_redirect = home_realm_signin_redirect(request, company=company, email=email)
            if realm_redirect is not None:
                return realm_redirect
        if company is not None and magic_link_enabled_for_company(company):
            limited = plain_response(
                _send_magic_link(request, company=company, email=email, lang=lang, rate_limit=False)
            )
            if limited is not None:
                return limited
        sent = True
    if parsed is not None:
        client_name = parsed.client.client_name or parsed.client.client_id
        cancel_url = mcp_cancel_return_url(parsed)
    else:
        client_name = device_grant.client.client_name or device_grant.client.client_id
        cancel_url = reverse('mcp-oauth-device')
    login_host = identity_login_host(request)
    strings = mcp_signin_page_strings(
        request, copy=copy, client_name=client_name, login_host=login_host
    )
    response = render(
        request,
        'agents/mcp_signin.html',
        {
            'page_language': lang,
            'copy': copy,
            'client_name': client_name,
            'login_host': login_host,
            'cancel_url': cancel_url,
            'sent': sent,
            **strings,
        },
    )
    return protect_page(response)


@xframe_options_deny
@require_http_methods(['GET'])
def mcp_signin_complete(request: HttpRequest) -> HttpResponse:
    """Landing for a direct visit. The sign-in flows finish in :func:`finish_mcp_signin`."""
    path, parsed = _saved_authorize(request)
    if path and parsed is not None and request.user.is_authenticated:
        return HttpResponseRedirect(path)
    from apps.agents.oauth_device import device_grant_for_signin

    grant, _error = device_grant_for_signin(request)
    if grant is not None and request.user.is_authenticated:
        return HttpResponseRedirect(reverse('mcp-oauth-device'))
    return render_message(request, copy_for(page_language(request))['session_lost'], 400)


def signin_redirect(request: HttpRequest, authorize_path: str, company_id: int) -> HttpResponse:
    remember_authorize(request, authorize_path, company_id)
    return HttpResponseRedirect(reverse('mcp-oauth-signin'))


def approval_redirect(redirect_uri: str, params: dict[str, str]) -> HttpResponseRedirect:
    sep = '&' if '?' in redirect_uri else '?'
    return HttpResponseRedirect(f'{redirect_uri}{sep}{urlencode(params)}')
