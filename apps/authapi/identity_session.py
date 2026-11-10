"""First-party identity browser session.

App login (OAuth, SSO, magic link) returns tokens to the shell and does not use them
as the browser session. This module also calls ``django.contrib.auth.login`` on that
same identity-origin response so later server-rendered pages can offer "Continue as".

The shell token APIs stay Bearer-only. ``GET|POST /oauth/logout`` clears only this
cookie. Refresh-token revocation stays on ``POST /api/v1/logout``.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.clickjacking import xframe_options_deny
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from apps.agents.mcp_signin import SESSION_BACKEND
from apps.authapi.login_audit import LoginOutcome, record_login_event
from apps.authapi.magic_link import is_staff_account

AUTH_TIME_KEY = 'identity_auth_time'
AUTH_METHOD_KEY = 'identity_auth_method'
AUTH_COMPANY_KEY = 'identity_auth_company_id'
CLI_CONTINUE_KEY = 'identity_cli_continue_grant'
MCP_AUTHORIZE_CONTINUE_KEY = 'identity_mcp_authorize_client'
MCP_DEVICE_CONTINUE_KEY = 'identity_mcp_device_grant'
MCP_APPROVAL_CONTINUE_KEY = 'identity_mcp_approval_id'
MAGIC_LINK_METHOD = 'magic_link'
_CLI_METHOD_KEY = 'cli_device_auth_method'

# Flow bindings that must survive "Use another account". Logout rotates the key.
_PRESERVE_SESSION_KEYS = (
    'cli_device_grant_id',
    'cli_device_user_code',
    'mcp_oauth_authorize_path',
    'mcp_oauth_company_id',
    'mcp_device_grant_id',
    'mcp_approval_return_path',
)

CONTINUE_COPY = {
    'en': {
        'continue_as': 'Continue as {email}',
        'use_another': 'Use another account',
        'signed_out_title': 'You are signed out',
        'signed_out_body': 'You can close this page.',
        'step_up': 'Sign in again with a password or single sign-on to continue.',
    },
    'fr': {
        'continue_as': 'Continuer en tant que {email}',
        'use_another': 'Utiliser un autre compte',
        'signed_out_title': 'Vous êtes déconnecté',
        'signed_out_body': 'Vous pouvez fermer cette page.',
        'step_up': "Reconnectez-vous avec un mot de passe ou l'authentification unique pour continuer.",
    },
}


def _django(request: HttpRequest) -> HttpRequest:
    return getattr(request, '_request', request)


def continue_copy(lang: str) -> dict[str, str]:
    return CONTINUE_COPY.get(lang) or CONTINUE_COPY['en']


def account_email(user) -> str:
    email = str(getattr(user, 'email', None) or '').strip()
    if email:
        return email
    return str(user.get_username() or '').strip()


def identity_session_max_age() -> timedelta:
    raw = getattr(settings, 'IDENTITY_SESSION_MAX_AGE', None)
    if not isinstance(raw, timedelta) or raw.total_seconds() <= 0:
        raw = getattr(settings, 'JWT_REFRESH_TOKEN_LIFETIME', timedelta(days=7))
    if not isinstance(raw, timedelta) or raw.total_seconds() <= 0:
        return timedelta(days=7)
    return raw


def user_can_use_company_session(user, company) -> bool:
    """Active user with access to ``company``. Otherwise the flow treats them as signed out."""
    if user is None or not getattr(user, 'is_authenticated', False):
        return False
    if not getattr(user, 'is_active', False):
        return False
    if company is None or not getattr(company, 'pk', None):
        return False
    from apps.agents.mcp_signin import is_company_member
    from apps.companies.access import is_company_access_enabled

    if not is_company_member(company, user):
        return False
    return is_company_access_enabled(company, user)


def staff_cli_needs_step_up(request, user) -> bool:
    """Staff CLI must use a fresh password or SSO session, not a magic-link session."""
    if not is_staff_account(user):
        return False
    django_request = _django(request)
    method = str(django_request.session.get(AUTH_METHOD_KEY) or '')
    cli_method = str(django_request.session.get(_CLI_METHOD_KEY) or '')
    if method == MAGIC_LINK_METHOD or cli_method == MAGIC_LINK_METHOD:
        return True
    raw = django_request.session.get(AUTH_TIME_KEY)
    if raw is None:
        return False
    try:
        auth_time = int(raw)
    except (TypeError, ValueError):
        return True
    from apps.authapi.cli_device import cli_staff_session_max_age

    return (timezone.now().timestamp() - auth_time) > cli_staff_session_max_age().total_seconds()


def establish_identity_session(request, user, *, company, method: str) -> bool:
    """Log ``user`` into the identity origin. Returns False when they cannot have a session.

    ``login`` rotates the session key. Staff sessions expire at ``CLI_STAFF_SESSION_MAX_AGE``.
    Everyone else uses ``IDENTITY_SESSION_MAX_AGE`` (the refresh-token lifetime unless set).
    """
    if not user_can_use_company_session(user, company):
        return False
    from django.contrib.auth import login

    from apps.authapi.cli_device import cli_staff_session_max_age
    from apps.authapi.user_activity import touch_user_last_seen
    from apps.federation.session import remember_provider_session

    django_request = _django(request)
    login(django_request, user, backend=SESSION_BACKEND)
    django_request.session[AUTH_TIME_KEY] = int(timezone.now().timestamp())
    django_request.session[AUTH_METHOD_KEY] = str(method or 'unknown')[:32]
    django_request.session[AUTH_COMPANY_KEY] = int(company.pk)
    expiry = identity_session_max_age()
    if is_staff_account(user):
        cap = cli_staff_session_max_age()
        if cap < expiry:
            expiry = cap
    django_request.session.set_expiry(max(1, int(expiry.total_seconds())))
    touch_user_last_seen(user)
    remember_provider_session(django_request, user)
    django_request._identity_session_started = True
    return True


def confirm_marker(request, key: str, value: str) -> None:
    _django(request).session[key] = value


def confirmed(request, key: str, value: str) -> bool:
    return str(_django(request).session.get(key) or '') == str(value)


def posted_account_choice(request) -> str:
    if getattr(request, 'method', '') != 'POST':
        return ''
    choice = str(request.POST.get('account_choice') or '').strip()
    if choice in {'continue', 'switch'}:
        return choice
    return ''


def end_identity_session(request, *, preserve_flow: bool = False) -> None:
    """Clear the identity browser session. Does not revoke refresh tokens."""
    django_request = _django(request)
    user = getattr(django_request, 'user', None)
    preserved: dict[str, object] = {}
    if preserve_flow:
        preserved = {
            key: django_request.session.get(key)
            for key in _PRESERVE_SESSION_KEYS
            if key in django_request.session
        }
    if user is not None and getattr(user, 'is_authenticated', False):
        method = str(django_request.session.get(AUTH_METHOD_KEY) or 'unknown')[:32]
        company = None
        raw_company = django_request.session.get(AUTH_COMPANY_KEY)
        if raw_company is not None:
            from apps.companies.models import Company

            company = Company.objects.filter(pk=raw_company).first()
        record_login_event(
            request=django_request,
            outcome=LoginOutcome.SUCCESS,
            provider=method,
            user=user,
            company=company,
            identity_session='ended',
        )
        logout(django_request)
    for key, value in preserved.items():
        if value not in (None, ''):
            django_request.session[key] = value


def render_continue_as(
    request,
    *,
    email: str,
    lead: str = '',
    hidden_fields: dict[str, str] | None = None,
) -> HttpResponse:
    from apps.agents.mcp_signin import page_language, protect_page

    lang = page_language(request, getattr(request, 'user', None))
    copy = continue_copy(lang)
    response = render(
        request,
        'authapi/continue_as.html',
        {
            'page_language': lang,
            'lead': lead,
            'continue_label': copy['continue_as'].format(email=email),
            'switch_label': copy['use_another'],
            'hidden_fields': hidden_fields or {},
        },
    )
    return protect_page(response)


def render_signed_out(request) -> HttpResponse:
    from apps.agents.mcp_signin import page_language, protect_page

    lang = page_language(request, None)
    copy = continue_copy(lang)
    response = render(
        request,
        'authapi/signed_out.html',
        {
            'page_language': lang,
            'title': copy['signed_out_title'],
            'message': copy['signed_out_body'],
        },
    )
    return protect_page(response)


def identity_logout_url(request) -> str:
    from django.core.exceptions import ImproperlyConfigured

    from apps.authapi.magic_link import identity_public_base_url

    try:
        base = identity_public_base_url(fallback=request.build_absolute_uri('/'))
    except ImproperlyConfigured:
        base = request.build_absolute_uri('/').rstrip('/')
    return f'{base.rstrip("/")}/oauth/logout'


def _logout_return_to(request) -> str | None:
    """Same allowlist as ``redirect_to`` on ``GET /api/v1/authorize``. None when it cannot be used."""
    from apps.companies.models import Company
    from apps.companies.redirect_allowlist import validate_redirect_to_for_company

    return_to = (request.GET.get('return_to') or request.POST.get('return_to') or '').strip()
    raw_company = request.GET.get('company_id')
    if raw_company in (None, '') and request.method == 'POST':
        raw_company = request.POST.get('company_id')
    if not return_to or raw_company in (None, ''):
        return None
    try:
        company_id = int(str(raw_company).strip())
    except (TypeError, ValueError):
        return None
    company = Company.objects.filter(pk=company_id).first()
    if company is None:
        return None
    url, err = validate_redirect_to_for_company(
        company=company,
        request=_django(request),
        redirect_to_raw=return_to,
    )
    if err or not url:
        return None
    return url


@xframe_options_deny
@csrf_protect
@require_http_methods(['GET', 'POST'])
def identity_browser_logout(request: HttpRequest) -> HttpResponse:
    """Clear the identity browser session and return to an allowlisted app URL.

    Does not revoke access or refresh tokens. ``return_to`` is checked with the
    company's redirect allowlist, the same rules as ``GET /api/v1/authorize``.
    A missing or rejected ``return_to`` renders the signed-out page.
    """
    target = _logout_return_to(request)
    end_identity_session(request, preserve_flow=False)
    if target:
        return HttpResponseRedirect(target)
    return render_signed_out(request)
