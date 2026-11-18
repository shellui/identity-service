"""Server-rendered sign-in for an OpenID client that requires a Shellui account.

Used by ai-service global. The consent page stays on ai.shellui.com. This page
only proves the Shellui account. Staff accounts are refused. Region-only
accounts are told to use their region's company MCP URL.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.contrib.auth.signals import user_logged_in
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_http_methods

from apps.agents.mcp_signin import page_language, protect_page
from apps.agents.staff import is_mcp_oauth_refused_user
from apps.authapi.throttling import check_rate_limit
from apps.federation.provider import (
    AuthorizeSpec,
    issue_authorization_redirect,
    load_authorize_request,
    render_authorize,
)
from apps.federation.session import clear_cookie, forget_provider_session, read_session, remember_verified_email, set_cookie

User = get_user_model()

# Not a real password hash. Makes the failure path do similar work.
_DUMMY_PASSWORD_HASH = 'pbkdf2_sha256$600000$oidsalt$invalidinvalidinvalidinvalidinvalidinvalidinvalid='

_COPY = {
    'en': {
        'title': 'Sign in with your Shellui account',
        'lead': 'Sign in with your Shellui account to continue.',
        'hint': (
            'ai.shellui.com/mcp is for Shellui accounts. If your company account is in one region, '
            'connect your region\'s AI URL instead: https://<regional ai>/c/<company_id>/mcp.'
        ),
        'docs': 'Docs',
        'email': 'Email',
        'password': 'Password',
        'submit': 'Sign in',
        'cancel': 'Cancel',
        'failed': 'The email or password is wrong.',
        'continue_as': 'Continue as {email}',
        'use_another': 'Use another account',
        'staff': 'Staff accounts cannot authorize MCP agents. Sign in with a Shellui account.',
    },
    'fr': {
        'title': 'Connectez-vous avec votre compte Shellui',
        'lead': 'Connectez-vous avec votre compte Shellui pour continuer.',
        'hint': (
            'ai.shellui.com/mcp est réservé aux comptes Shellui. Si votre compte d\'entreprise est '
            'dans une seule région, connectez l\'URL d\'IA de cette région : '
            'https://<regional ai>/c/<company_id>/mcp.'
        ),
        'docs': 'Documentation',
        'email': 'E-mail',
        'password': 'Mot de passe',
        'submit': 'Se connecter',
        'cancel': 'Annuler',
        'failed': 'L\'e-mail ou le mot de passe est incorrect.',
        'continue_as': 'Continuer en tant que {email}',
        'use_another': 'Utiliser un autre compte',
        'staff': 'Les comptes staff ne peuvent pas autoriser d\'agents MCP. Connectez-vous avec un compte Shellui.',
    },
}

DOCS_URL = 'https://docs.shellui.com'


def _copy(request, user=None) -> dict[str, str]:
    lang = page_language(request, user)
    return _COPY.get(lang) or _COPY['en']


def _account_email(user) -> str:
    email = str(getattr(user, 'email', None) or '').strip()
    if email:
        return email
    return str(user.get_username() or '').strip()


def render_login_page(
    request: HttpRequest,
    spec: AuthorizeSpec,
    *,
    signed_in=None,
    error: str = '',
) -> HttpResponse:
    copy = _copy(request, signed_in)
    response = render(
        request,
        'federation/oidc_login.html',
        {
            'page_language': page_language(request, signed_in),
            'copy': copy,
            'lead': copy['lead'],
            'hint': copy['hint'],
            'docs_url': DOCS_URL,
            'error': error,
            'cancel_url': _cancel_url(spec),
            'signed_in_email': _account_email(signed_in) if signed_in is not None else '',
            'continue_label': copy['continue_as'].format(email=_account_email(signed_in)) if signed_in is not None else '',
        },
    )
    return protect_page(response)


def render_staff_refused(request: HttpRequest, spec: AuthorizeSpec) -> HttpResponse:
    copy = _copy(request)
    response = render(
        request,
        'federation/oidc_login.html',
        {
            'page_language': page_language(request),
            'copy': copy,
            'lead': copy['staff'],
            'hint': copy['hint'],
            'docs_url': DOCS_URL,
            'error': '',
            'cancel_url': _cancel_url(spec),
            'signed_in_email': '',
            'continue_label': '',
            'staff_refused': True,
        },
        status=403,
    )
    return protect_page(response)


def _cancel_url(spec: AuthorizeSpec) -> str:
    from apps.federation.provider import _redirect_error

    return _redirect_error(spec.redirect_uri, 'access_denied', spec.state)['Location']


@ensure_csrf_cookie
@csrf_protect
@require_http_methods(['GET', 'POST'])
def oauth_authorize(request: HttpRequest):
    """``GET /oauth/authorize`` plus the Shellui account sign-in form."""
    if request.method == 'POST':
        return _login_post(request)
    from apps.federation.provider import AuthorizeView

    return AuthorizeView.as_view()(request)


def _login_post(request: HttpRequest) -> HttpResponse:
    limited = check_rate_limit(request, scope='oauth')
    if limited is not None:
        return JsonResponse(limited.data, status=limited.status_code, headers={'Retry-After': '60'})
    loaded = load_authorize_request(request)
    if not isinstance(loaded, AuthorizeSpec):
        return loaded
    if not loaded.shellui_account_required:
        from apps.federation.provider import _redirect_error

        return _redirect_error(loaded.redirect_uri, 'interaction_required', loaded.state)
    choice = str(request.POST.get('account_choice') or '').strip()
    if choice == 'switch':
        forget_provider_session(request)
        response = render_login_page(request, loaded)
        clear_cookie(response)
        return response
    session = read_session(request)
    if choice == 'continue' and loaded.prompt != 'login' and session is not None:
        user, sid = session
        if is_mcp_oauth_refused_user(user):
            return render_staff_refused(request, loaded)
        return issue_authorization_redirect(loaded, user, sid)
    if loaded.prompt != 'login' and session is not None and choice != 'password':
        return render_authorize(request, loaded)
    return _password_post(request, loaded)


def _password_post(request: HttpRequest, spec: AuthorizeSpec) -> HttpResponse:
    email = str(request.POST.get('email') or '').strip()
    password = str(request.POST.get('password') or '')
    copy = _copy(request)
    if not email or '@' not in email or len(email) > 254 or not password or len(password) > 256:
        check_password(password or 'x', _DUMMY_PASSWORD_HASH)
        return render_login_page(request, spec, error=copy['failed'])
    account = User.objects.filter(email__iexact=email, is_active=True).order_by('id').first()
    if account is None or not account.has_usable_password():
        check_password(password, _DUMMY_PASSWORD_HASH)
        return render_login_page(request, spec, error=copy['failed'])
    from django.contrib.auth import authenticate

    authed = authenticate(request, username=account.get_username(), password=password)
    if authed is None or not getattr(authed, 'is_active', False):
        return render_login_page(request, spec, error=copy['failed'])
    if is_mcp_oauth_refused_user(authed):
        return render_staff_refused(request, spec)
    remember_verified_email(authed, getattr(authed, 'email', '') or email)
    user_logged_in.send(sender=authed.__class__, request=request, user=authed)
    response = HttpResponseRedirect(spec.redirect_uri)
    sid = set_cookie(response, authed)
    return issue_authorization_redirect(spec, authed, sid, response=response)
