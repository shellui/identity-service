"""OAuth 2.0 Device Authorization Grant (RFC 8628) for the Shellui CLI.

Separate from the MCP device grant. A CLI device code never becomes an agent token,
and an MCP device code never becomes an app session. Approval returns the same app
session tokens as ``POST /api/v1/oauth/session``. Codes are stored as SHA-256 hashes.
"""

from __future__ import annotations

import logging
import secrets
from datetime import timedelta, timezone as dt_timezone
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.clickjacking import xframe_options_deny
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView

from apps.agents.mcp_signin import (
    is_company_member,
    page_language,
    plain_response,
    protect_page,
)
from apps.agents.oauth_codes import hash_authorization_code
from apps.agents.oauth_device import (
    USER_CODE_ALPHABET,
    USER_CODE_LENGTH,
    format_user_code,
    normalize_user_code,
)
from apps.agents.oauth_request_body import parse_oauth_post_body
from apps.authapi.cli_device_copy import copy_for, error_message
from apps.authapi.login_audit import LoginOutcome, get_client_ip, record_login_event, truncate_user_agent
from apps.authapi.magic_link import is_staff_account
from apps.authapi.models import CliDeviceAuthorization
from apps.authapi.serializers import ShellUIOpenAPISerializer
from apps.authapi.throttling import check_rate_limit
from apps.companies.access import is_company_access_enabled
from apps.companies.models import Company

logger = logging.getLogger(__name__)

CLI_CLIENT_ID = CliDeviceAuthorization.CLIENT_ID
CLI_KIND = CliDeviceAuthorization.KIND_CLI
DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'
DEVICE_VERIFY_PATH = '/oauth/cli/device'
DEVICE_AUTHORIZATION_PATH = '/oauth/cli/device/code'
SIGNIN_COMPLETE_PATH = '/oauth/cli/signin/complete'
DEVICE_EXPIRES_IN = 600
DEVICE_INTERVAL = 5
SLOW_DOWN_STEP = 5
MAX_POLL_INTERVAL = 300

CLI_DEVICE_GRANT_SESSION_KEY = 'cli_device_grant_id'
CLI_DEVICE_USER_CODE_SESSION_KEY = 'cli_device_user_code'
CLI_DEVICE_AUTH_METHOD_SESSION_KEY = 'cli_device_auth_method'
AUTH_METHOD_MAGIC_LINK = 'magic_link'
AUTH_METHOD_PASSWORD = 'password'


def cli_staff_session_max_age() -> timedelta:
    raw = getattr(settings, 'CLI_STAFF_SESSION_MAX_AGE', timedelta(hours=12))
    if not isinstance(raw, timedelta) or raw.total_seconds() <= 0:
        raw = timedelta(hours=12)
    normal = settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME')
    if isinstance(normal, timedelta) and raw > normal:
        return normal
    return raw


def staff_refresh_bounds(user) -> tuple[timedelta | None, int | None]:
    """``(refresh lifetime, absolute unix exp)`` for a staff CLI session, else ``(None, None)``."""
    if not is_staff_account(user):
        return None, None
    lifetime = cli_staff_session_max_age()
    cap = int((timezone.now() + lifetime).timestamp())
    return lifetime, cap


def _public_base(request: HttpRequest | None) -> str:
    from apps.authapi.magic_link import identity_public_base_url
    from django.core.exceptions import ImproperlyConfigured

    fallback = request.build_absolute_uri('/') if request is not None else None
    try:
        return identity_public_base_url(fallback=fallback)
    except ImproperlyConfigured:
        return (fallback or '').rstrip('/')


def cli_signin_complete_url(request: HttpRequest | None = None) -> str:
    base = _public_base(request)
    return f'{base}{SIGNIN_COMPLETE_PATH}' if base else ''


def is_cli_signin_redirect(url: str | None) -> bool:
    """True when a sign-in flow's ``redirect_to`` is the CLI device landing on this identity."""
    target = str(url or '').strip()
    expected = cli_signin_complete_url()
    return bool(target and expected and target == expected)


def _django_request(request) -> HttpRequest:
    return getattr(request, '_request', request)


def _device_error(error: str, *, status: int = 400, description: str | None = None) -> JsonResponse:
    payload: dict[str, str] = {'error': error}
    if description:
        payload['error_description'] = description
    response = JsonResponse(payload, status=status)
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    return response


def _device_json(payload: dict, *, status: int = 200) -> JsonResponse:
    response = JsonResponse(payload, status=status)
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    return response


def _new_user_code() -> tuple[str, str]:
    canonical = ''.join(secrets.choice(USER_CODE_ALPHABET) for _ in range(USER_CODE_LENGTH))
    return format_user_code(canonical), canonical


def _parse_company_id(raw) -> int | None:
    if raw is None or isinstance(raw, bool):
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        parsed = int(text)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


class CliDeviceAuthorizationRequestSerializer(serializers.Serializer):
    client_id = serializers.CharField(help_text='Must be shellui-cli.')
    company_id = serializers.IntegerField(help_text='Company the CLI is signing in to.')


class CliDeviceAuthorizationResponseSerializer(serializers.Serializer):
    device_code = serializers.CharField()
    user_code = serializers.CharField()
    verification_uri = serializers.CharField()
    verification_uri_complete = serializers.CharField()
    expires_in = serializers.IntegerField()
    interval = serializers.IntegerField()


class CliDeviceAuthorizationView(APIView):
    """RFC 8628 device authorization endpoint for the Shellui CLI."""

    authentication_classes = []
    permission_classes = []
    serializer_class = ShellUIOpenAPISerializer

    @extend_schema(
        tags=['auth-session'],
        operation_id='oauth_cli_device_authorization',
        auth=[],
        summary='Start a Shellui CLI device login',
        description=(
            'RFC 8628 device authorization for the Shellui CLI (`client_id=shellui-cli`). '
            'Send `client_id` and `company_id` as `application/x-www-form-urlencoded` or JSON. '
            'The response includes `device_code`, `user_code` (`XXXX-XXXX`), `verification_uri`, '
            '`verification_uri_complete`, `expires_in` (600), and `interval` (5). '
            'Poll `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`, '
            '`client_id=shellui-cli`, and `device_code`. '
            'While the person has not finished, the token endpoint returns `authorization_pending`. '
            'Polling faster than `interval` returns `slow_down` (add 5 seconds before the next poll). '
            'A denial returns `access_denied`. An unused code past `expires_in` returns `expired_token`. '
            'The device code is single-use. Codes are stored as hashes and are not logged. '
            'After approval the token response is a normal app session for that company '
            '(`access_token`, `refresh_token`, `token_type`, `expires_in`, `expires_at`), '
            'the same shape as `POST /api/v1/oauth/session`. Refresh it at '
            '`POST /api/v1/token?grant_type=refresh_token`. '
            'An MCP device code is not accepted here, and this device code is not an MCP token. '
            'Staff accounts can approve with a password or SSO. Magic link is not offered to staff. '
            'A staff CLI refresh token is capped by `CLI_STAFF_SESSION_MAX_AGE` (default 12 hours).'
        ),
        request=CliDeviceAuthorizationRequestSerializer,
        responses={
            200: CliDeviceAuthorizationResponseSerializer,
            400: OpenApiResponse(description='invalid_request'),
            401: OpenApiResponse(description='invalid_client'),
            429: OpenApiResponse(description='Too many device authorization requests'),
        },
    )
    def post(self, request):
        django_request = _django_request(request)
        limited = check_rate_limit(django_request, scope='cli_device_code')
        if limited is not None:
            return limited
        return issue_cli_device_authorization(django_request)


def issue_cli_device_authorization(request: HttpRequest) -> JsonResponse:
    body, parse_err = parse_oauth_post_body(request)
    if parse_err is not None:
        parse_err['Cache-Control'] = 'no-store'
        parse_err['Pragma'] = 'no-cache'
        return parse_err
    assert body is not None
    client_id = str(body.get('client_id') or '').strip()
    if not client_id:
        return _device_error('invalid_request', description='client_id is required.')
    if client_id != CLI_CLIENT_ID:
        return _device_error('invalid_client', status=401, description='Unknown client.')
    company_id = _parse_company_id(body.get('company_id'))
    if company_id is None:
        return _device_error('invalid_request', description='company_id is required.')
    company = Company.objects.filter(pk=company_id).first()
    if company is None:
        return _device_error('invalid_request', description='Unknown company.')
    expires_at = timezone.now() + timedelta(seconds=DEVICE_EXPIRES_IN)
    row = None
    device_plain = ''
    display = ''
    for _attempt in range(8):
        device_plain = secrets.token_urlsafe(32)
        display, canonical = _new_user_code()
        try:
            with transaction.atomic():
                row = CliDeviceAuthorization.objects.create(
                    kind=CLI_KIND,
                    client_id=CLI_CLIENT_ID,
                    device_code_digest=hash_authorization_code(device_plain),
                    user_code_digest=hash_authorization_code(canonical),
                    company=company,
                    poll_interval=DEVICE_INTERVAL,
                    expires_at=expires_at,
                    request_ip=(get_client_ip(request) or '')[:64],
                    request_user_agent=truncate_user_agent(request.META.get('HTTP_USER_AGENT')),
                )
            break
        except IntegrityError:
            row = None
            continue
    if row is None:
        logger.info('cli_device_code_issue_failed company_id=%s client_id=%s', company.pk, CLI_CLIENT_ID)
        return _device_error('server_error', status=500, description='Could not issue a device code.')
    verify = f'{_public_base(request)}{DEVICE_VERIFY_PATH}'
    logger.info('cli_device_code_issued company_id=%s client_id=%s', company.pk, CLI_CLIENT_ID)
    return _device_json(
        {
            'device_code': device_plain,
            'user_code': display,
            'verification_uri': verify,
            'verification_uri_complete': f'{verify}?{urlencode({"user_code": display})}',
            'expires_in': DEVICE_EXPIRES_IN,
            'interval': DEVICE_INTERVAL,
        }
    )


def handle_cli_device_code_grant(body: dict) -> JsonResponse:
    """Token endpoint branch for a Shellui CLI device code. Never reads MCP device rows."""
    device_code = str(body.get('device_code') or '').strip()
    client_id = str(body.get('client_id') or '').strip()
    if not device_code or not client_id:
        return _device_error('invalid_request', description='device_code and client_id are required.')
    if client_id != CLI_CLIENT_ID:
        return _device_error('invalid_client', status=401, description='Unknown client.')
    digest = hash_authorization_code(device_code)
    with transaction.atomic():
        try:
            row = (
                CliDeviceAuthorization.objects.select_for_update(of=('self',))
                .select_related('user', 'company')
                .get(device_code_digest=digest)
            )
        except CliDeviceAuthorization.DoesNotExist:
            return _device_error('invalid_grant', description='The device code is not valid.')
        if row.client_id != CLI_CLIENT_ID or row.kind != CLI_KIND:
            return _device_error('invalid_grant', description='The device code is not valid.')
        now = timezone.now()
        if row.status == CliDeviceAuthorization.STATUS_CONSUMED or row.consumed_at is not None:
            return _device_error('invalid_grant', description='The device code was already used.')
        if row.status == CliDeviceAuthorization.STATUS_DENIED:
            return _device_error('access_denied', description='The user denied this request.')
        if row.status == CliDeviceAuthorization.STATUS_EXPIRED or row.expires_at <= now:
            if row.status != CliDeviceAuthorization.STATUS_EXPIRED:
                row.status = CliDeviceAuthorization.STATUS_EXPIRED
                row.save(update_fields=['status'])
            return _device_error('expired_token', description='The device code has expired.')
        if row.status == CliDeviceAuthorization.STATUS_APPROVED:
            return _issue_approved_locked(row, now)
        if row.status != CliDeviceAuthorization.STATUS_PENDING:
            return _device_error('invalid_grant', description='The device code is not valid.')
        interval = int(row.poll_interval or DEVICE_INTERVAL)
        if row.last_poll_at is not None and (now - row.last_poll_at).total_seconds() < interval:
            row.poll_interval = min(interval + SLOW_DOWN_STEP, MAX_POLL_INTERVAL)
            row.last_poll_at = now
            row.save(update_fields=['poll_interval', 'last_poll_at'])
            return _device_error('slow_down', description='Polling too frequently.')
        row.last_poll_at = now
        row.save(update_fields=['last_poll_at'])
    return _device_error('authorization_pending', description='The user has not approved this request.')


def _issue_approved_locked(row: CliDeviceAuthorization, now) -> JsonResponse:
    user = row.user
    company = row.company
    if (
        user is None
        or not user.is_active
        or company is None
        or not is_company_member(company, user)
        or not is_company_access_enabled(company, user)
    ):
        row.status = CliDeviceAuthorization.STATUS_DENIED
        row.denied_at = now
        row.save(update_fields=['status', 'denied_at'])
        return _device_error('access_denied', description='The user denied this request.')
    from apps.authapi.views import _issue_shellui_tokens

    lifetime, cap = staff_refresh_bounds(user)
    provider = (row.auth_provider or 'cli')[:32]
    try:
        payload = _issue_shellui_tokens(
            user,
            company=company,
            oauth_provider=provider,
            refresh_lifetime=lifetime,
            session_max_exp=cap,
            session_kind=CLI_KIND,
            session_user_agent=row.request_user_agent,
        )
    except PermissionDenied:
        row.status = CliDeviceAuthorization.STATUS_DENIED
        row.denied_at = now
        row.save(update_fields=['status', 'denied_at'])
        return _device_error('access_denied', description='The user denied this request.')
    row.status = CliDeviceAuthorization.STATUS_CONSUMED
    row.consumed_at = now
    row.save(update_fields=['status', 'consumed_at'])
    logger.info('cli_device_session_issued company_id=%s user_id=%s', company.pk, user.pk)
    return _device_json(payload)


def _render_error(request: HttpRequest, code: str, status: int = 400, *, user=None) -> HttpResponse:
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


def _render_message(request: HttpRequest, message: str, status: int = 200, *, user=None) -> HttpResponse:
    lang = page_language(request, user)
    copy = copy_for(lang)
    response = render(
        request,
        'agents/mcp_error.html',
        {
            'page_language': lang,
            'copy': copy,
            'title': copy['error_title'],
            'message': message,
            'error_code': '',
        },
        status=status,
    )
    return protect_page(response)


def _render_result(request: HttpRequest, *, title: str, message: str, user=None) -> HttpResponse:
    lang = page_language(request, user)
    copy = copy_for(lang)
    response = render(
        request,
        'agents/mcp_device_result.html',
        {
            'page_language': lang,
            'copy': copy,
            'title': title,
            'message': message,
        },
    )
    return protect_page(response)


def remember_cli_grant(request: HttpRequest, grant_id: str, user_code: str, auth_method: str | None = None) -> None:
    request.session[CLI_DEVICE_GRANT_SESSION_KEY] = str(grant_id)
    if user_code:
        request.session[CLI_DEVICE_USER_CODE_SESSION_KEY] = user_code
    if auth_method:
        request.session[CLI_DEVICE_AUTH_METHOD_SESSION_KEY] = auth_method


def clear_cli_grant(request: HttpRequest) -> None:
    request.session.pop(CLI_DEVICE_GRANT_SESSION_KEY, None)
    request.session.pop(CLI_DEVICE_USER_CODE_SESSION_KEY, None)
    request.session.pop(CLI_DEVICE_AUTH_METHOD_SESSION_KEY, None)


def _grant_from_session(request: HttpRequest) -> CliDeviceAuthorization | None:
    raw = request.session.get(CLI_DEVICE_GRANT_SESSION_KEY)
    if not raw:
        return None
    try:
        return CliDeviceAuthorization.objects.select_related('company', 'user').get(pk=raw)
    except (CliDeviceAuthorization.DoesNotExist, ValueError, ValidationError):
        return None


def _lookup_user_code(canonical: str) -> CliDeviceAuthorization | None:
    return (
        CliDeviceAuthorization.objects.select_related('company', 'user')
        .filter(user_code_digest=hash_authorization_code(canonical), kind=CLI_KIND, client_id=CLI_CLIENT_ID)
        .first()
    )


def _format_requested_at(stamp) -> str:
    if stamp is None:
        return ''
    aware = stamp if timezone.is_aware(stamp) else timezone.make_aware(stamp, dt_timezone.utc)
    return aware.astimezone(dt_timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def _member_block(request: HttpRequest, grant: CliDeviceAuthorization, user) -> HttpResponse | None:
    copy = copy_for(page_language(request, user))
    if not getattr(user, 'is_active', False):
        return _render_message(request, copy['not_member'].format(company=grant.company.name), 403, user=user)
    if not is_company_member(grant.company, user):
        return _render_message(request, copy['not_member'].format(company=grant.company.name), 403, user=user)
    if not is_company_access_enabled(grant.company, user):
        return _render_message(request, copy['access_disabled'], 403, user=user)
    return None


def finish_cli_signin(request: HttpRequest, *, user, company: Company, auth_method: str) -> HttpResponse:
    """Finish magic-link or SSO sign-in that started from the CLI verification page."""
    grant = _grant_from_session(request)
    user_code = str(request.session.get(CLI_DEVICE_USER_CODE_SESSION_KEY) or '')
    copy = copy_for(page_language(request, user))
    if grant is None:
        return _render_message(request, copy['session_lost'], 400, user=user)
    if grant.company_id != company.id:
        return _render_message(request, copy['session_lost'], 400, user=user)
    if is_staff_account(user) and auth_method == AUTH_METHOD_MAGIC_LINK:
        return _render_message(request, copy['staff_magic_refused'], 403, user=user)
    blocked = _member_block(request, grant, user)
    if blocked is not None:
        return blocked
    from apps.authapi.identity_session import CLI_CONTINUE_KEY, establish_identity_session

    if not establish_identity_session(request, user, company=company, method=auth_method):
        return _member_block(request, grant, user) or _render_message(
            request, copy['not_member'].format(company=company.name), 403, user=user
        )
    remember_cli_grant(request, str(grant.id), user_code, auth_method)
    request.session[CLI_CONTINUE_KEY] = str(grant.id)
    return HttpResponseRedirect(reverse('cli-oauth-device'))


def _safe_prefill(raw: str) -> str:
    canonical = normalize_user_code(raw)
    if not canonical:
        return ''
    return format_user_code(canonical)


def _render_code_form(request: HttpRequest, *, prefill: str) -> HttpResponse:
    lang = page_language(request, request.user if request.user.is_authenticated else None)
    copy = copy_for(lang)
    lead = copy['code_lead_prefilled'] if prefill else copy['code_lead']
    response = render(
        request,
        'authapi/cli_device_code.html',
        {
            'page_language': lang,
            'copy': copy,
            'lead': lead,
            'prefill': prefill,
        },
    )
    return protect_page(response)


def _provider_links(request: HttpRequest, company: Company) -> list[dict[str, str]]:
    from apps.authapi.client_pkce import s256_challenge
    from apps.authapi.views import _build_shellui_authorize_url, _enabled_oauth_providers, _provider_display_label

    lang = page_language(request)
    copy = copy_for(lang)
    verifier = secrets.token_urlsafe(48)
    challenge = s256_challenge(verifier)
    redirect_to = cli_signin_complete_url(request)
    links: list[dict[str, str]] = []
    for provider in _enabled_oauth_providers(company):
        label = _provider_display_label(provider)
        links.append(
            {
                'label': copy['provider_button'].format(provider=label),
                'url': _build_shellui_authorize_url(
                    request,
                    company=company,
                    redirect_to=redirect_to,
                    provider=provider,
                    code_challenge=challenge,
                ),
            }
        )
    return links


def _render_signin(
    request: HttpRequest,
    grant: CliDeviceAuthorization,
    *,
    sent: bool = False,
    email_unavailable: bool = False,
    password_error: str = '',
    step_up: bool = False,
) -> HttpResponse:
    from apps.authapi.magic_link import magic_link_enabled_for_company

    from apps.authapi.identity_session import continue_copy

    lang = page_language(request, request.user if request.user.is_authenticated else None)
    copy = copy_for(lang)
    magic_on = magic_link_enabled_for_company(grant.company)
    response = render(
        request,
        'authapi/cli_device_signin.html',
        {
            'page_language': lang,
            'copy': copy,
            'lead': copy['signin_lead'].format(company=grant.company.name),
            'sent': sent,
            'email_sent': copy['email_sent'].format(company=grant.company.name),
            'email_unavailable': email_unavailable or not magic_on,
            'password_error': password_error,
            'magic_link_enabled': magic_on,
            'providers': _provider_links(request, grant.company),
            'step_up': step_up,
            'step_up_message': continue_copy(lang)['step_up'] if step_up else '',
        },
    )
    return protect_page(response)


def _render_consent(request: HttpRequest, grant: CliDeviceAuthorization, user) -> HttpResponse:
    lang = page_language(request, user)
    copy = copy_for(lang)
    shown = str(request.session.get(CLI_DEVICE_USER_CODE_SESSION_KEY) or '')
    response = render(
        request,
        'authapi/cli_device_consent.html',
        {
            'page_language': lang,
            'copy': copy,
            'lead': copy['signin_lead'].format(company=grant.company.name),
            'signed_in_as': copy['signed_in_as'].format(email=user.email or user.get_username()),
            'company_name': grant.company.name,
            'requested_at': _format_requested_at(grant.created_at),
            'request_ip': grant.request_ip or copy['unknown'],
            'request_user_agent': grant.request_user_agent or copy['unknown'],
            'user_code': shown,
        },
    )
    return protect_page(response)


def _send_cli_magic_link(request: HttpRequest, *, company: Company, email: str) -> HttpResponse | None:
    from apps.authapi import magic_link_views as mlv
    from apps.authapi.magic_link import create_magic_link_token, staff_account_for_email

    limited = plain_response(mlv._magic_link_rate_limits(request, company_id=company.id, email=email))
    if limited is not None:
        return limited
    existing = mlv.User.objects.filter(email__iexact=email).first()
    if mlv.is_login_blocked_by_revoked_invitation(company, email, existing):
        return None
    staff_user = existing if is_staff_account(existing) else staff_account_for_email(email)
    if staff_user is not None:
        logger.info('cli_device_magic_link_staff_refused company_id=%s', company.pk)
        return None
    with transaction.atomic():
        row, raw_token = create_magic_link_token(
            company=company,
            email=email,
            redirect_to=cli_signin_complete_url(request),
            user=existing,
        )
        mlv._deliver_or_error_response(
            lambda: mlv.deliver_magic_link_email(
                row=row,
                company=company,
                user=existing,
                language=page_language(request, existing),
                raw_token=raw_token,
                fallback_base_url=request.build_absolute_uri('/'),
            ),
            company=company,
            request_id=row.pk,
        )
    return None


def _post_password(request: HttpRequest, grant: CliDeviceAuthorization) -> HttpResponse:
    limited = plain_response(check_rate_limit(request, scope='cli_device_verify'))
    if limited is not None:
        return limited
    copy = copy_for(page_language(request))
    email = str(request.POST.get('email') or '').strip().lower()
    password = str(request.POST.get('password') or '')
    if not email or '@' not in email or len(email) > 254 or not password or len(password) > 256:
        return _render_signin(request, grant, password_error=copy['password_failed'])
    from django.contrib.auth import get_user_model

    account = get_user_model().objects.filter(email__iexact=email, is_active=True).first()
    authed = None
    if account is not None and account.has_usable_password():
        authed = authenticate(request, username=account.get_username(), password=password)
    if authed is None:
        record_login_event(
            request=request,
            outcome=LoginOutcome.FAILURE,
            provider=AUTH_METHOD_PASSWORD,
            user=None,
            company=grant.company,
            failure_reason='invalid_credentials',
        )
        return _render_signin(request, grant, password_error=copy['password_failed'])
    response = finish_cli_signin(request, user=authed, company=grant.company, auth_method=AUTH_METHOD_PASSWORD)
    if response.status_code in (301, 302):
        record_login_event(
            request=request,
            outcome=LoginOutcome.SUCCESS,
            provider=AUTH_METHOD_PASSWORD,
            user=authed,
            company=grant.company,
        )
    return response


def _post_email(request: HttpRequest, grant: CliDeviceAuthorization) -> HttpResponse:
    from apps.authapi.magic_link import magic_link_enabled_for_company
    from apps.agents.mcp_home_realm import home_realm_signin_redirect
    from apps.authapi.client_pkce import s256_challenge

    email = str(request.POST.get('email') or '').strip().lower()
    if not email or '@' not in email or len(email) > 254:
        return _render_error(request, 'invalid_request', 400)
    if not magic_link_enabled_for_company(grant.company):
        challenge = s256_challenge(secrets.token_urlsafe(48))
        realm = home_realm_signin_redirect(
            request,
            company=grant.company,
            email=email,
            redirect_to=cli_signin_complete_url(request),
            code_challenge=challenge,
        )
        if realm is not None:
            return realm
        return _render_signin(request, grant, email_unavailable=True)
    challenge = s256_challenge(secrets.token_urlsafe(48))
    realm = home_realm_signin_redirect(
        request,
        company=grant.company,
        email=email,
        redirect_to=cli_signin_complete_url(request),
        code_challenge=challenge,
    )
    if realm is not None:
        return realm
    limited = _send_cli_magic_link(request, company=grant.company, email=email)
    if limited is not None:
        return limited
    return _render_signin(request, grant, sent=True)


def _cli_session_block(request: HttpRequest, grant: CliDeviceAuthorization) -> str:
    """``step_up``, ``signed_out``, or ``''`` when Continue as is allowed."""
    from apps.authapi.identity_session import staff_cli_needs_step_up, user_can_use_company_session

    user = request.user
    if not getattr(user, 'is_authenticated', False):
        return 'signed_out'
    if staff_cli_needs_step_up(request, user):
        return 'step_up'
    if not user_can_use_company_session(user, grant.company):
        return 'signed_out'
    return ''


def _render_cli_continue(request: HttpRequest, grant: CliDeviceAuthorization) -> HttpResponse:
    from apps.authapi.identity_session import account_email, render_continue_as

    copy = copy_for(page_language(request, request.user))
    return render_continue_as(
        request,
        email=account_email(request.user),
        lead=copy['signin_lead'].format(company=grant.company.name),
    )


def _handle_cli_account_choice(request: HttpRequest, grant: CliDeviceAuthorization) -> HttpResponse | None:
    from apps.authapi.identity_session import CLI_CONTINUE_KEY, end_identity_session, posted_account_choice

    choice = posted_account_choice(request)
    if choice == 'switch':
        end_identity_session(request, preserve_flow=True)
        return HttpResponseRedirect(reverse('cli-oauth-signin'))
    if choice != 'continue':
        return None
    block = _cli_session_block(request, grant)
    if block:
        return _render_signin(request, grant, step_up=block == 'step_up')
    request.session[CLI_CONTINUE_KEY] = str(grant.id)
    return _redirect_device()


@xframe_options_deny
@csrf_protect
@require_http_methods(['GET', 'POST'])
def cli_device_signin(request: HttpRequest) -> HttpResponse:
    from apps.authapi.identity_session import CLI_CONTINUE_KEY, confirmed

    grant = _grant_from_session(request)
    if grant is None or grant.status != CliDeviceAuthorization.STATUS_PENDING or grant.expires_at <= timezone.now():
        if grant is not None and grant.expires_at <= timezone.now():
            return _render_error(request, 'device_code_expired', 400)
        return _render_error(request, 'invalid_request', 400)
    chosen = _handle_cli_account_choice(request, grant)
    if chosen is not None:
        return chosen
    block = _cli_session_block(request, grant)
    if block == '' and confirmed(request, CLI_CONTINUE_KEY, str(grant.id)):
        return _redirect_device()
    if request.method == 'GET' and block == '':
        return _render_cli_continue(request, grant)
    if request.method == 'POST':
        if 'password' in request.POST:
            return _post_password(request, grant)
        return _post_email(request, grant)
    return _render_signin(request, grant, step_up=block == 'step_up')


@xframe_options_deny
@require_http_methods(['GET'])
def cli_device_signin_complete(request: HttpRequest) -> HttpResponse:
    """Landing for a direct visit. Magic link and SSO finish in :func:`finish_cli_signin`."""
    grant = _grant_from_session(request)
    if grant is not None and request.user.is_authenticated:
        return HttpResponseRedirect(reverse('cli-oauth-device'))
    return _render_message(request, copy_for(page_language(request))['session_lost'], 400)


def _redirect_device() -> HttpResponseRedirect:
    return HttpResponseRedirect(reverse('cli-oauth-device'))


def _post_user_code(request: HttpRequest) -> HttpResponse:
    limited = plain_response(check_rate_limit(request, scope='cli_device_verify'))
    if limited is not None:
        return limited
    canonical = normalize_user_code(request.POST.get('user_code'))
    if not canonical:
        return _render_error(request, 'device_code_invalid', 400)
    grant = _lookup_user_code(canonical)
    if grant is None:
        return _render_error(request, 'device_code_invalid', 400)
    now = timezone.now()
    if grant.expires_at <= now or grant.status == CliDeviceAuthorization.STATUS_EXPIRED:
        if grant.status != CliDeviceAuthorization.STATUS_EXPIRED:
            with transaction.atomic():
                locked = CliDeviceAuthorization.objects.select_for_update().get(pk=grant.pk)
                if locked.status == CliDeviceAuthorization.STATUS_PENDING:
                    locked.status = CliDeviceAuthorization.STATUS_EXPIRED
                    locked.save(update_fields=['status'])
        return _render_error(request, 'device_code_expired', 400)
    if grant.status == CliDeviceAuthorization.STATUS_DENIED:
        return _render_error(request, 'device_code_denied', 400)
    display = format_user_code(canonical)
    if grant.status in {CliDeviceAuthorization.STATUS_CONSUMED, CliDeviceAuthorization.STATUS_APPROVED}:
        remember_cli_grant(request, str(grant.id), display)
        return _redirect_device()
    if grant.status != CliDeviceAuthorization.STATUS_PENDING:
        return _render_error(request, 'device_code_invalid', 400)
    remember_cli_grant(request, str(grant.id), display)
    if _cli_session_block(request, grant):
        return HttpResponseRedirect(reverse('cli-oauth-signin'))
    return _redirect_device()


def _deny_grant(request: HttpRequest, grant: CliDeviceAuthorization, user) -> HttpResponse | None:
    blocked = _member_block(request, grant, user)
    if blocked is not None:
        return blocked
    now = timezone.now()
    with transaction.atomic():
        locked = CliDeviceAuthorization.objects.select_for_update().get(pk=grant.pk)
        if locked.status == CliDeviceAuthorization.STATUS_DENIED:
            return None
        if locked.expires_at <= now or locked.status == CliDeviceAuthorization.STATUS_EXPIRED:
            if locked.status != CliDeviceAuthorization.STATUS_EXPIRED:
                locked.status = CliDeviceAuthorization.STATUS_EXPIRED
                locked.save(update_fields=['status'])
            return _render_error(request, 'device_code_expired', 400, user=user)
        if locked.status != CliDeviceAuthorization.STATUS_PENDING:
            return _render_error(request, 'device_code_used', 400, user=user)
        locked.status = CliDeviceAuthorization.STATUS_DENIED
        locked.user = user
        locked.denied_at = now
        locked.save(update_fields=['status', 'user', 'denied_at'])
    return None


def _approve_grant(request: HttpRequest, grant: CliDeviceAuthorization, user) -> HttpResponse | None:
    blocked = _member_block(request, grant, user)
    if blocked is not None:
        return blocked
    method = str(request.session.get(CLI_DEVICE_AUTH_METHOD_SESSION_KEY) or 'cli')
    if is_staff_account(user) and method == AUTH_METHOD_MAGIC_LINK:
        copy = copy_for(page_language(request, user))
        return _render_message(request, copy['staff_magic_refused'], 403, user=user)
    now = timezone.now()
    with transaction.atomic():
        locked = (
            CliDeviceAuthorization.objects.select_for_update()
            .select_related('company')
            .get(pk=grant.pk)
        )
        if locked.expires_at <= now or locked.status == CliDeviceAuthorization.STATUS_EXPIRED:
            if locked.status != CliDeviceAuthorization.STATUS_EXPIRED:
                locked.status = CliDeviceAuthorization.STATUS_EXPIRED
                locked.save(update_fields=['status'])
            return _render_error(request, 'device_code_expired', 400, user=user)
        if locked.status == CliDeviceAuthorization.STATUS_DENIED:
            return _render_error(request, 'device_code_denied', 400, user=user)
        if locked.status != CliDeviceAuthorization.STATUS_PENDING:
            return _render_error(request, 'device_code_used', 400, user=user)
        if locked.kind != CLI_KIND or locked.client_id != CLI_CLIENT_ID:
            return _render_error(request, 'device_code_invalid', 400, user=user)
        locked.status = CliDeviceAuthorization.STATUS_APPROVED
        locked.user = user
        locked.approved_at = now
        locked.auth_provider = method[:32]
        locked.save(update_fields=['status', 'user', 'approved_at', 'auth_provider'])
    from apps.authapi.views import _notify_user_logged_in_for_oauth

    _notify_user_logged_in_for_oauth(request, user)
    record_login_event(
        request=request,
        outcome=LoginOutcome.SUCCESS,
        provider='cli',
        user=user,
        company=grant.company,
        device_kind=CLI_KIND,
        audit_ip=grant.request_ip or None,
        audit_user_agent=grant.request_user_agent or None,
    )
    logger.info('cli_device_approved company_id=%s user_id=%s', grant.company_id, user.pk)
    return None


def _post_decision(request: HttpRequest) -> HttpResponse:
    if not request.user.is_authenticated:
        return _render_error(request, 'invalid_request', 400)
    user = request.user
    grant = _grant_from_session(request)
    if grant is None:
        return _render_error(request, 'invalid_request', 400, user=user)
    if _cli_session_block(request, grant) == 'step_up':
        return HttpResponseRedirect(reverse('cli-oauth-signin'))
    decision = str(request.POST.get('decision') or '').strip()
    if decision == 'deny':
        error = _deny_grant(request, grant, user)
        if error is not None:
            return error
        return _redirect_device()
    if decision != 'approve':
        return _render_error(request, 'invalid_request', 400, user=user)
    error = _approve_grant(request, grant, user)
    if error is not None:
        return error
    return _redirect_device()


def _render_grant_state(request: HttpRequest, grant: CliDeviceAuthorization) -> HttpResponse:
    user = request.user if request.user.is_authenticated else None
    copy = copy_for(page_language(request, user))
    now = timezone.now()
    if grant.expires_at <= now or grant.status == CliDeviceAuthorization.STATUS_EXPIRED:
        clear_cli_grant(request)
        return _render_error(request, 'device_code_expired', 400, user=user)
    if grant.status == CliDeviceAuthorization.STATUS_DENIED:
        clear_cli_grant(request)
        return _render_result(request, title=copy['denied'], message='', user=user)
    if grant.status == CliDeviceAuthorization.STATUS_CONSUMED:
        clear_cli_grant(request)
        return _render_error(request, 'device_code_used', 400, user=user)
    if grant.status == CliDeviceAuthorization.STATUS_APPROVED:
        clear_cli_grant(request)
        return _render_result(request, title=copy['approved_title'], message=copy['approved'], user=user)
    if grant.status != CliDeviceAuthorization.STATUS_PENDING:
        clear_cli_grant(request)
        return _render_error(request, 'device_code_invalid', 400, user=user)
    block = _cli_session_block(request, grant)
    if block:
        return HttpResponseRedirect(reverse('cli-oauth-signin'))
    from apps.authapi.identity_session import CLI_CONTINUE_KEY, confirmed

    if not confirmed(request, CLI_CONTINUE_KEY, str(grant.id)):
        return _render_cli_continue(request, grant)
    method = str(request.session.get(CLI_DEVICE_AUTH_METHOD_SESSION_KEY) or '')
    if is_staff_account(request.user) and method == AUTH_METHOD_MAGIC_LINK:
        return _render_message(request, copy['staff_magic_refused'], 403, user=request.user)
    return _render_consent(request, grant, request.user)


@xframe_options_deny
@csrf_protect
@require_http_methods(['GET', 'POST'])
def cli_device_verification(request: HttpRequest) -> HttpResponse:
    """Browser page at ``verification_uri``. Enter the user code, sign in, then approve or deny."""
    if request.method == 'POST' and str(request.POST.get('account_choice') or '').strip():
        grant = _grant_from_session(request)
        if grant is None:
            return _render_error(request, 'invalid_request', 400)
        chosen = _handle_cli_account_choice(request, grant)
        if chosen is not None:
            return chosen
        return _render_error(request, 'invalid_request', 400)
    if request.method == 'POST' and str(request.POST.get('decision') or '').strip():
        return _post_decision(request)
    if request.method == 'POST':
        return _post_user_code(request)
    prefill_raw = str(request.GET.get('user_code') or '')
    if prefill_raw.strip():
        clear_cli_grant(request)
        return _render_code_form(request, prefill=_safe_prefill(prefill_raw))
    grant = _grant_from_session(request)
    if grant is None:
        return _render_code_form(request, prefill='')
    return _render_grant_state(request, grant)
