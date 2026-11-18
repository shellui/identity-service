"""OAuth 2.0 Device Authorization Grant (RFC 8628) for company MCP clients.

Headless agents poll the token endpoint. A person approves in the browser. The device
code and the user code are stored as hashes and are never written to logs.
"""

from __future__ import annotations

import logging
import secrets
from datetime import timedelta
from urllib.parse import urlencode

from django.conf import settings
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
from rest_framework.views import APIView

from apps.agents.mcp_copy import copy_for
from apps.agents.mcp_resources import GATEWAY_SERVICE_ID, resolve_mcp_resource, resource_company_id
from apps.agents.mcp_signin import (
    DEVICE_GRANT_SESSION_KEY,
    clear_device_grant,
    is_company_member,
    page_language,
    plain_response,
    protect_page,
    remember_device_grant,
    render_error,
    render_message,
)
from apps.agents.models import Agent, McpCallLog, McpDeviceAuthorization, McpOAuthClient
from apps.agents.oauth_codes import hash_authorization_code
from apps.agents.oauth_request_body import parse_oauth_post_body
from apps.agents.personal_agent_tokens import personal_agent_max_lifetime
from apps.agents.staff import is_mcp_oauth_refused_user
from apps.agents.tokens import encode_access_token, issue_agent_refresh, mcp_access_lifetime, revoke_all_agent_refresh_sessions
from apps.authapi.serializers import ShellUIOpenAPISerializer
from apps.authapi.throttling import check_rate_limit
from apps.companies.models import Company

logger = logging.getLogger(__name__)

DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'
DEVICE_VERIFY_PATH = '/oauth/mcp/device'
DEVICE_AUTHORIZATION_PATH = '/oauth/mcp/device/code'
USER_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
USER_CODE_LENGTH = 8
SLOW_DOWN_STEP = 5
MAX_POLL_INTERVAL = 300

_PENDING_ERRORS = {
    McpDeviceAuthorization.STATUS_DENIED: 'device_code_denied',
    McpDeviceAuthorization.STATUS_EXPIRED: 'device_code_expired',
    McpDeviceAuthorization.STATUS_CONSUMED: 'device_code_used',
    McpDeviceAuthorization.STATUS_APPROVED: 'device_code_used',
}


def device_code_lifetime() -> timedelta:
    seconds = int(getattr(settings, 'MCP_DEVICE_CODE_LIFETIME_SECONDS', 600) or 600)
    return timedelta(seconds=max(60, min(seconds, 1800)))


def device_poll_interval() -> int:
    raw = int(getattr(settings, 'MCP_DEVICE_CODE_INTERVAL_SECONDS', 5) or 5)
    return max(5, min(raw, 60))


def device_authorization_endpoint(base: str) -> str:
    return f'{base.rstrip("/")}{DEVICE_AUTHORIZATION_PATH}'


def device_verification_uri(base: str) -> str:
    return f'{base.rstrip("/")}{DEVICE_VERIFY_PATH}'


def normalize_user_code(raw: str | None) -> str | None:
    """Canonical 8-character code, or None when the text is not a user code."""
    compact = ''.join(ch for ch in str(raw or '').upper() if not ch.isspace() and ch != '-')
    if len(compact) != USER_CODE_LENGTH:
        return None
    if any(ch not in USER_CODE_ALPHABET for ch in compact):
        return None
    return compact


def format_user_code(canonical: str) -> str:
    return f'{canonical[:4]}-{canonical[4:]}'


def _public_base(request: HttpRequest | None) -> str:
    base = str(getattr(settings, 'JWT_ISSUER', '') or '').strip().rstrip('/')
    if not base and request is not None:
        base = request.build_absolute_uri('/').rstrip('/')
    return base


def _django_request(request) -> HttpRequest:
    return getattr(request, '_request', request)


def _registration_allowed(company: Company) -> bool:
    if not getattr(settings, 'MCP_DYNAMIC_CLIENT_REGISTRATION', True):
        return False
    return bool(getattr(company, 'mcp_allow_dynamic_registration', True))


def _device_error(
    error: str,
    *,
    status: int = 400,
    description: str | None = None,
) -> JsonResponse:
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


def _scope_text(body: dict) -> str:
    raw = body.get('scope')
    if isinstance(raw, list):
        text = ' '.join(str(item) for item in raw)
    else:
        text = str(raw or '')
    return ' '.join(text.split())[:500]


def _new_user_code() -> tuple[str, str]:
    canonical = ''.join(secrets.choice(USER_CODE_ALPHABET) for _ in range(USER_CODE_LENGTH))
    return format_user_code(canonical), canonical


class DeviceAuthorizationRequestSerializer(serializers.Serializer):
    client_id = serializers.CharField()
    resource = serializers.CharField(
        help_text='Company MCP URL: {AI_SERVICE_URL}/c/<company_id>/mcp.',
    )
    scope = serializers.CharField(required=False, allow_blank=True)


class DeviceAuthorizationResponseSerializer(serializers.Serializer):
    device_code = serializers.CharField()
    user_code = serializers.CharField()
    verification_uri = serializers.CharField()
    verification_uri_complete = serializers.CharField()
    expires_in = serializers.IntegerField()
    interval = serializers.IntegerField()


class DeviceAuthorizationView(APIView):
    """RFC 8628 device authorization endpoint for one company MCP resource."""

    authentication_classes = []
    permission_classes = []
    serializer_class = ShellUIOpenAPISerializer

    @extend_schema(
        tags=['mcp-oauth'],
        operation_id='oauth_mcp_device_authorization',
        auth=[],
        summary='Start an MCP device login',
        description=(
            'RFC 8628 device authorization for a company MCP resource. '
            'Send `client_id` and `resource` (`{AI_SERVICE_URL}/c/<company_id>/mcp`) as '
            '`application/x-www-form-urlencoded` or JSON. '
            'The response includes `device_code`, `user_code`, `verification_uri`, '
            '`verification_uri_complete`, `expires_in` (about 10 minutes), and `interval` (5 seconds). '
            'Poll `POST /oauth/token` (or `POST /oauth/mcp/token`) with '
            '`grant_type=urn:ietf:params:oauth:grant-type:device_code`, the same `client_id`, '
            '`device_code`, and `resource`. '
            'While the person has not finished, the token endpoint returns `authorization_pending`. '
            'Polling faster than `interval` returns `slow_down` (add 5 seconds before the next poll). '
            'A denial returns `access_denied`. An unused code past `expires_in` returns `expired_token`. '
            'The device code is single-use. Codes are stored as hashes and are not logged. '
            'After approval the token response matches the authorization-code grant: a short-lived '
            'access token and a refresh token. `aud` is the company MCP URL.'
        ),
        request=DeviceAuthorizationRequestSerializer,
        responses={
            200: DeviceAuthorizationResponseSerializer,
            400: OpenApiResponse(description='invalid_request or invalid_target'),
            401: OpenApiResponse(description='invalid_client'),
            403: OpenApiResponse(description='registration_disabled'),
            429: OpenApiResponse(description='Too many device authorization requests'),
        },
    )
    def post(self, request):
        django_request = _django_request(request)
        limited = check_rate_limit(django_request, scope='mcp_device_code')
        if limited is not None:
            return limited
        return issue_device_authorization(django_request)


def issue_device_authorization(request: HttpRequest) -> JsonResponse:
    body, parse_err = parse_oauth_post_body(request)
    if parse_err is not None:
        parse_err['Cache-Control'] = 'no-store'
        parse_err['Pragma'] = 'no-cache'
        return parse_err
    assert body is not None
    client_id = str(body.get('client_id') or '').strip()
    if not client_id:
        return _device_error('invalid_request', description='client_id is required.')
    client = McpOAuthClient.objects.filter(client_id=client_id).first()
    if client is None:
        return _device_error('invalid_client', status=401, description='Unknown client.')
    resource_raw = str(body.get('resource') or '').strip()
    if not resource_raw:
        return _device_error('invalid_request', description='resource is required.')
    resource_url, service_id = resolve_mcp_resource(resource_raw)
    company_id = resource_company_id(resource_url) if resource_url else None
    if not resource_url or service_id != GATEWAY_SERVICE_ID or company_id is None:
        return _device_error('invalid_target', description='resource must be the company MCP URL.')
    company = Company.objects.filter(pk=company_id, deletion_requested_at__isnull=True).first()
    if company is None:
        return _device_error('invalid_target', description='resource must be the company MCP URL.')
    if not _registration_allowed(company):
        return _device_error(
            'registration_disabled',
            status=403,
            description='This company does not allow new MCP clients.',
        )
    lifetime = device_code_lifetime()
    interval = device_poll_interval()
    expires_at = timezone.now() + lifetime
    scope = _scope_text(body)
    row = None
    display = ''
    device_plain = ''
    for _attempt in range(8):
        device_plain = secrets.token_urlsafe(32)
        display, canonical = _new_user_code()
        try:
            with transaction.atomic():
                row = McpDeviceAuthorization.objects.create(
                    device_code_digest=hash_authorization_code(device_plain),
                    user_code_digest=hash_authorization_code(canonical),
                    client=client,
                    company=company,
                    resource=resource_url,
                    scope=scope,
                    poll_interval=interval,
                    expires_at=expires_at,
                )
            break
        except IntegrityError:
            row = None
            continue
    if row is None:
        logger.info('mcp_device_code_issue_failed company_id=%s client_id=%s', company.pk, client.client_id)
        return _device_error('server_error', status=500, description='Could not issue a device code.')
    base = _public_base(request)
    verify = device_verification_uri(base)
    logger.info('mcp_device_code_issued company_id=%s client_id=%s', company.pk, client.client_id)
    return _device_json(
        {
            'device_code': device_plain,
            'user_code': display,
            'verification_uri': verify,
            'verification_uri_complete': f'{verify}?{urlencode({"user_code": display})}',
            'expires_in': int(lifetime.total_seconds()),
            'interval': interval,
        }
    )


def handle_device_code_grant(body: dict) -> JsonResponse:
    """Token endpoint branch for ``grant_type=urn:ietf:params:oauth:grant-type:device_code``."""
    device_code = str(body.get('device_code') or '').strip()
    client_id = str(body.get('client_id') or '').strip()
    if not device_code or not client_id:
        return _device_error('invalid_request', description='device_code and client_id are required.')
    client = McpOAuthClient.objects.filter(client_id=client_id).first()
    if client is None:
        return _device_error('invalid_client', status=401, description='Unknown client.')
    resource_raw = str(body.get('resource') or '').strip()
    resource_url, service_id = resolve_mcp_resource(resource_raw)
    if not resource_url or service_id != GATEWAY_SERVICE_ID:
        return _device_error('invalid_target', description='resource must be the company MCP URL.')
    digest = hash_authorization_code(device_code)
    with transaction.atomic():
        try:
            # agent/user are nullable → LEFT OUTER JOIN. Postgres rejects FOR UPDATE on
            # that side; of=('self',) locks only the device row (same as approval locks).
            row = (
                McpDeviceAuthorization.objects.select_for_update(of=('self',))
                .select_related('client', 'agent', 'user', 'company')
                .get(device_code_digest=digest)
            )
        except McpDeviceAuthorization.DoesNotExist:
            return _device_error('invalid_grant', description='The device code is not valid.')
        if row.client_id != client.id:
            return _device_error('invalid_grant', description='The device code is not valid.')
        if row.resource != resource_url or resource_company_id(resource_url) != row.company_id:
            return _device_error('invalid_target', description='resource does not match this device code.')
        now = timezone.now()
        if row.status == McpDeviceAuthorization.STATUS_CONSUMED or row.consumed_at is not None:
            return _device_error('invalid_grant', description='The device code was already used.')
        if row.status == McpDeviceAuthorization.STATUS_DENIED:
            return _device_error('access_denied', description='The user denied this request.')
        if row.status == McpDeviceAuthorization.STATUS_EXPIRED or row.expires_at <= now:
            _expire_locked(row, now)
            return _device_error('expired_token', description='The device code has expired.')
        if row.status == McpDeviceAuthorization.STATUS_APPROVED:
            return _issue_approved_locked(row, now)
        if row.status != McpDeviceAuthorization.STATUS_PENDING:
            return _device_error('invalid_grant', description='The device code is not valid.')
        interval = int(row.poll_interval or device_poll_interval())
        if row.last_poll_at is not None and (now - row.last_poll_at).total_seconds() < interval:
            row.poll_interval = min(interval + SLOW_DOWN_STEP, MAX_POLL_INTERVAL)
            row.last_poll_at = now
            row.save(update_fields=['poll_interval', 'last_poll_at'])
            return _device_error('slow_down', description='Polling too frequently.')
        row.last_poll_at = now
        row.save(update_fields=['last_poll_at'])
    return _device_error('authorization_pending', description='The user has not approved this request.')


def _expire_locked(row: McpDeviceAuthorization, now) -> None:
    if row.status == McpDeviceAuthorization.STATUS_CONSUMED or row.consumed_at is not None:
        return
    row.status = McpDeviceAuthorization.STATUS_EXPIRED
    row.save(update_fields=['status'])
    agent = row.agent
    if agent is not None and agent.revoked_at is None:
        agent.revoked_at = now
        agent.save(update_fields=['revoked_at', 'updated_at'])
        revoke_all_agent_refresh_sessions(agent)


def _issue_approved_locked(row: McpDeviceAuthorization, now) -> JsonResponse:
    agent = row.agent
    approver = row.user
    if (
        agent is None
        or approver is None
        or not agent.is_active
        or is_mcp_oauth_refused_user(approver)
    ):
        row.status = McpDeviceAuthorization.STATUS_DENIED
        row.denied_at = now
        row.save(update_fields=['status', 'denied_at'])
        return _device_error('access_denied', description='The user denied this request.')
    try:
        access = encode_access_token(agent, resource=row.resource)
        refresh, _session = issue_agent_refresh(agent, resource=row.resource)
    except ValueError:
        row.status = McpDeviceAuthorization.STATUS_DENIED
        row.denied_at = now
        row.save(update_fields=['status', 'denied_at'])
        return _device_error('access_denied', description='The user denied this request.')
    row.status = McpDeviceAuthorization.STATUS_CONSUMED
    row.consumed_at = now
    row.save(update_fields=['status', 'consumed_at'])
    return _device_json(
        {
            'access_token': access,
            'token_type': 'Bearer',
            'expires_in': int(mcp_access_lifetime().total_seconds()),
            'refresh_token': refresh,
        }
    )


def device_grant_for_signin(request: HttpRequest) -> tuple[McpDeviceAuthorization | None, str | None]:
    """Pending device grant saved on this browser, or an error code when that grant is finished."""
    raw = request.session.get(DEVICE_GRANT_SESSION_KEY)
    if not raw:
        return None, None
    try:
        grant = McpDeviceAuthorization.objects.select_related('client', 'company').get(pk=raw)
    except (McpDeviceAuthorization.DoesNotExist, ValueError, ValidationError):
        return None, None
    now = timezone.now()
    if grant.status == McpDeviceAuthorization.STATUS_PENDING and grant.expires_at > now:
        return grant, None
    if grant.expires_at <= now or grant.status == McpDeviceAuthorization.STATUS_EXPIRED:
        return None, 'device_code_expired'
    return None, _PENDING_ERRORS.get(grant.status, 'invalid_request')


def finish_device_signin(request: HttpRequest, *, user, company: Company, method: str = '') -> HttpResponse:
    """Finish magic-link or SSO sign-in that started from the device verification page."""
    grant, error = device_grant_for_signin(request)
    copy = copy_for(page_language(request, user))
    if grant is None:
        if error:
            return render_error(request, error, 400, user=user)
        return render_message(request, copy['session_lost'], 400, user=user)
    if grant.company_id != company.id:
        return render_message(request, copy['session_lost'], 400, user=user)
    if is_mcp_oauth_refused_user(user):
        return render_message(request, copy['staff_refused'], 403, user=user)
    if not is_company_member(company, user):
        return render_message(request, copy['not_member'].format(company=company.name), 403, user=user)
    from apps.authapi.identity_session import MCP_DEVICE_CONTINUE_KEY, establish_identity_session

    if not establish_identity_session(request, user, company=company, method=method or 'sso'):
        return render_message(request, copy['not_member'].format(company=company.name), 403, user=user)
    remember_device_grant(request, str(grant.id))
    request.session[MCP_DEVICE_CONTINUE_KEY] = str(grant.id)
    return HttpResponseRedirect(reverse('mcp-oauth-device'))


def _grant_from_session(request: HttpRequest) -> McpDeviceAuthorization | None:
    raw = request.session.get(DEVICE_GRANT_SESSION_KEY)
    if not raw:
        return None
    try:
        return McpDeviceAuthorization.objects.select_related('client', 'company', 'user', 'agent').get(pk=raw)
    except (McpDeviceAuthorization.DoesNotExist, ValueError, ValidationError):
        return None


def _lookup_user_code(canonical: str) -> McpDeviceAuthorization | None:
    return (
        McpDeviceAuthorization.objects.select_related('client', 'company', 'user', 'agent')
        .filter(user_code_digest=hash_authorization_code(canonical))
        .first()
    )


def _render_code_form(request: HttpRequest, *, prefill: str) -> HttpResponse:
    lang = page_language(request, request.user if request.user.is_authenticated else None)
    copy = copy_for(lang)
    lead = copy['device_lead_prefilled'] if prefill else copy['device_lead']
    response = render(
        request,
        'agents/mcp_device_code.html',
        {
            'page_language': lang,
            'copy': copy,
            'lead': lead,
            'prefill': prefill,
        },
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


def _safe_prefill(raw: str) -> str:
    canonical = normalize_user_code(raw)
    if not canonical:
        return ''
    return format_user_code(canonical)


def _consent_context(request: HttpRequest, grant: McpDeviceAuthorization, user) -> dict:
    lang = page_language(request, user)
    copy = copy_for(lang)
    client_name = grant.client.client_name or grant.client.client_id
    services = [
        (sid, label)
        for sid, label in Agent.SERVICE_CHOICES
        if sid not in {Agent.SERVICE_AI, Agent.SERVICE_SAAS}
    ]
    days = personal_agent_max_lifetime().days
    return {
        'page_language': lang,
        'copy': copy,
        'consent_title': copy['consent_title'].format(client_name=client_name),
        'consent_body': copy['consent_body'].format(client_name=client_name, company_name=grant.company.name),
        'phishing': copy['phishing'].format(client_name=client_name),
        'signed_in_as': copy['signed_in_as'].format(email=user.email or user.get_username()),
        'lifetime_note': copy['device_lifetime_note'].format(days=days),
        'client_name': client_name,
        'company_name': grant.company.name,
        'services': services,
        'saas_opt_in_offered': device_saas_offered(),
    }


def device_saas_offered() -> bool:
    return bool(str(getattr(settings, 'SAAS_SERVICE_URL', '') or '').strip())


def _render_consent(request: HttpRequest, grant: McpDeviceAuthorization, user) -> HttpResponse:
    response = render(request, 'agents/mcp_device_consent.html', _consent_context(request, grant, user))
    return protect_page(response)


def _member_block(request: HttpRequest, grant: McpDeviceAuthorization, user) -> HttpResponse | None:
    copy = copy_for(page_language(request, user))
    if is_mcp_oauth_refused_user(user):
        return render_message(request, copy['staff_refused'], 403, user=user)
    if grant.company_id is None or not is_company_member(grant.company, user):
        return render_message(request, copy['not_member'].format(company=grant.company.name), 403, user=user)
    if not _registration_allowed(grant.company):
        return render_error(request, 'registration_disabled', 403, user=user)
    return None


def _normalize_services(posted: list[str]) -> list[str] | None:
    allowed = {choice[0] for choice in Agent.SERVICE_CHOICES}
    services = [s for s in posted if s in allowed and s != Agent.SERVICE_AI]
    if not services:
        return None
    if GATEWAY_SERVICE_ID not in services:
        services.append(GATEWAY_SERVICE_ID)
    return services


def _clamp_access(access_mode: str, read_level: str) -> tuple[str, str]:
    if access_mode not in {Agent.ACCESS_READ_ONLY, Agent.ACCESS_ASK, Agent.ACCESS_FULL}:
        access_mode = Agent.ACCESS_ASK
    if read_level not in {Agent.READ_SAFE, Agent.READ_SENSITIVE}:
        read_level = Agent.READ_SAFE
    return access_mode, read_level


def _write_approval(
    request: HttpRequest,
    *,
    user,
    grant: McpDeviceAuthorization,
    name: str,
    access_mode: str,
    read_level: str,
    services: list[str],
) -> HttpResponse | None:
    """Create the agent and mark the grant approved. Returns an error response, or None on success."""
    blocked = _member_block(request, grant, user)
    if blocked is not None:
        return blocked
    access_mode, read_level = _clamp_access(access_mode, read_level)
    cleaned = _normalize_services(services)
    if not cleaned:
        return render_error(request, 'invalid_request', 400, user=user)
    client = grant.client
    company = grant.company
    agent_name = ' '.join(str(name or '').split())[:255] or (client.client_name or 'MCP agent')[:255]
    now = timezone.now()
    with transaction.atomic():
        locked = (
            McpDeviceAuthorization.objects.select_for_update()
            .select_related('client', 'company')
            .get(pk=grant.pk)
        )
        if locked.expires_at <= now or locked.status == McpDeviceAuthorization.STATUS_EXPIRED:
            _expire_locked(locked, now)
            return render_error(request, 'device_code_expired', 400, user=user)
        if locked.status == McpDeviceAuthorization.STATUS_DENIED:
            return render_error(request, 'device_code_denied', 400, user=user)
        if locked.status != McpDeviceAuthorization.STATUS_PENDING:
            return render_error(request, 'device_code_used', 400, user=user)
        agent = Agent.objects.create(
            company=company,
            name=agent_name,
            oauth_client=client,
            created_by=user,
            access_mode=access_mode,
            allow_destructive_without_asking=False,
            read_level=read_level,
            services_allowed=cleaned,
            expires_at=now + personal_agent_max_lifetime(),
        )
        locked.status = McpDeviceAuthorization.STATUS_APPROVED
        locked.user = user
        locked.agent = agent
        locked.approved_at = now
        locked.save(update_fields=['status', 'user', 'agent', 'approved_at'])
        McpCallLog.objects.create(
            agent=agent,
            company=company,
            service='identity',
            tool='oauth.device.approved',
            http_method='POST',
            path='/oauth/mcp/device',
            status_code=200,
            arguments_redacted={
                'client_id': client.client_id,
                'client_name': (client.client_name or '')[:255],
                'resource': locked.resource,
                'services': cleaned,
                'access_mode': access_mode,
                'read_level': read_level,
                'allow_destructive': False,
                'approved_by_user_id': user.pk,
                'grant_type': DEVICE_CODE_GRANT,
            },
        )
    logger.info('mcp_device_approved company_id=%s agent_id=%s', company.pk, agent.id)
    grant.status = McpDeviceAuthorization.STATUS_APPROVED
    return None


def _deny_grant(request: HttpRequest, grant: McpDeviceAuthorization, user) -> HttpResponse | None:
    blocked = _member_block(request, grant, user)
    if blocked is not None:
        return blocked
    now = timezone.now()
    with transaction.atomic():
        locked = McpDeviceAuthorization.objects.select_for_update().get(pk=grant.pk)
        if locked.status == McpDeviceAuthorization.STATUS_DENIED:
            return None
        if locked.expires_at <= now or locked.status == McpDeviceAuthorization.STATUS_EXPIRED:
            _expire_locked(locked, now)
            return render_error(request, 'device_code_expired', 400, user=user)
        if locked.status != McpDeviceAuthorization.STATUS_PENDING:
            return render_error(request, 'device_code_used', 400, user=user)
        locked.status = McpDeviceAuthorization.STATUS_DENIED
        locked.user = user
        locked.denied_at = now
        locked.save(update_fields=['status', 'user', 'denied_at'])
    return None


def _redirect_device() -> HttpResponseRedirect:
    return HttpResponseRedirect(reverse('mcp-oauth-device'))


def _device_session_block(request: HttpRequest, grant: McpDeviceAuthorization) -> str:
    """``staff``, ``signed_out``, or ``''`` when Continue as is allowed."""
    from apps.authapi.identity_session import user_can_use_company_session

    user = request.user
    if not getattr(user, 'is_authenticated', False):
        return 'signed_out'
    if is_mcp_oauth_refused_user(user):
        return 'staff'
    if not user_can_use_company_session(user, grant.company):
        return 'signed_out'
    return ''


def _render_device_continue(request: HttpRequest, grant: McpDeviceAuthorization) -> HttpResponse:
    from apps.authapi.identity_session import account_email, render_continue_as

    copy = copy_for(page_language(request, request.user))
    client_name = grant.client.client_name or grant.client.client_id
    return render_continue_as(
        request,
        email=account_email(request.user),
        lead=copy['why_signin'].format(client_name=client_name, company_name=copy['signin_company_name']),
    )


def _handle_device_account_choice(request: HttpRequest, grant: McpDeviceAuthorization) -> HttpResponse | None:
    from apps.authapi.identity_session import MCP_DEVICE_CONTINUE_KEY, end_identity_session, posted_account_choice

    choice = posted_account_choice(request)
    if not choice:
        return None
    if choice == 'switch' or _device_session_block(request, grant):
        if choice == 'switch':
            end_identity_session(request, preserve_flow=True)
        if _device_session_block(request, grant) == 'staff':
            refused = _member_block(request, grant, request.user)
            if refused is not None:
                return refused
        return HttpResponseRedirect(reverse('mcp-oauth-signin'))
    request.session[MCP_DEVICE_CONTINUE_KEY] = str(grant.id)
    return _redirect_device()


def _post_user_code(request: HttpRequest) -> HttpResponse:
    limited = plain_response(check_rate_limit(request, scope='mcp_device_verify'))
    if limited is not None:
        return limited
    canonical = normalize_user_code(request.POST.get('user_code'))
    if not canonical:
        return render_error(request, 'device_code_invalid', 400)
    grant = _lookup_user_code(canonical)
    if grant is None:
        return render_error(request, 'device_code_invalid', 400)
    now = timezone.now()
    if grant.expires_at <= now or grant.status == McpDeviceAuthorization.STATUS_EXPIRED:
        if grant.status != McpDeviceAuthorization.STATUS_EXPIRED:
            with transaction.atomic():
                locked = McpDeviceAuthorization.objects.select_for_update().get(pk=grant.pk)
                _expire_locked(locked, now)
        return render_error(request, 'device_code_expired', 400)
    if grant.status == McpDeviceAuthorization.STATUS_DENIED:
        return render_error(request, 'device_code_denied', 400)
    if grant.status in {McpDeviceAuthorization.STATUS_CONSUMED, McpDeviceAuthorization.STATUS_APPROVED}:
        remember_device_grant(request, str(grant.id))
        return _redirect_device()
    if grant.status != McpDeviceAuthorization.STATUS_PENDING:
        return render_error(request, 'device_code_invalid', 400)
    remember_device_grant(request, str(grant.id))
    block = _device_session_block(request, grant)
    if block == 'staff':
        refused = _member_block(request, grant, request.user)
        if refused is not None:
            return refused
    if block:
        return HttpResponseRedirect(reverse('mcp-oauth-signin'))
    return _redirect_device()


def _maybe_global_saas_signin(request, *, user, company, grant, name, access_mode, read_level, services, include_saas):
    if not include_saas or not device_saas_offered():
        return None
    from apps.agents.exchange import agent_exchange_enabled
    from apps.agents.mcp_saas_consent import (
        remember_saas_offered,
        saas_opt_in_requires_global_signin,
        start_global_identity_signin,
        store_pending_consent,
    )

    remember_saas_offered(request, offered=True)
    if not (agent_exchange_enabled() and saas_opt_in_requires_global_signin(include_saas=True, request=request)):
        return None
    if is_mcp_oauth_refused_user(user):
        return render_message(request, copy_for(page_language(request, user))['staff_refused'], 403, user=user)
    store_pending_consent(
        request,
        {
            'device_grant_id': str(grant.id),
            'name': name,
            'access_mode': access_mode,
            'read_level': read_level,
            'services': services,
            'include_saas': True,
        },
    )
    return start_global_identity_signin(request, company_id=company.id)


def _post_decision(request: HttpRequest) -> HttpResponse:
    if not request.user.is_authenticated:
        return render_error(request, 'invalid_request', 400)
    user = request.user
    grant = _grant_from_session(request)
    if grant is None:
        return render_error(request, 'invalid_request', 400, user=user)
    decision = str(request.POST.get('decision') or '').strip()
    if decision == 'deny':
        error = _deny_grant(request, grant, user)
        if error is not None:
            return error
        return _redirect_device()
    if decision != 'approve':
        return render_error(request, 'invalid_request', 400, user=user)
    name = (request.POST.get('agent_name') or grant.client.client_name or 'MCP agent')[:255]
    access_mode, read_level = _clamp_access(
        str(request.POST.get('access_mode') or ''),
        str(request.POST.get('read_level') or ''),
    )
    services = _normalize_services(request.POST.getlist('services'))
    if not services:
        return render_error(request, 'invalid_request', 400, user=user)
    include_saas = request.POST.get('include_saas') == 'on' and device_saas_offered()
    if include_saas:
        redirect = _maybe_global_saas_signin(
            request,
            user=user,
            company=grant.company,
            grant=grant,
            name=name,
            access_mode=access_mode,
            read_level=read_level,
            services=services,
            include_saas=True,
        )
        if redirect is not None:
            return redirect
        if Agent.SERVICE_SAAS not in services:
            services = [*services, Agent.SERVICE_SAAS]
    error = _write_approval(
        request,
        user=user,
        grant=grant,
        name=name,
        access_mode=access_mode,
        read_level=read_level,
        services=services,
    )
    if error is not None:
        return error
    return _redirect_device()


def _render_grant_state(request: HttpRequest, grant: McpDeviceAuthorization) -> HttpResponse:
    user = request.user if request.user.is_authenticated else None
    copy = copy_for(page_language(request, user))
    now = timezone.now()
    if grant.expires_at <= now or grant.status == McpDeviceAuthorization.STATUS_EXPIRED:
        if grant.status != McpDeviceAuthorization.STATUS_EXPIRED:
            with transaction.atomic():
                locked = (
                    McpDeviceAuthorization.objects.select_for_update(of=('self',))
                    .select_related('agent')
                    .get(pk=grant.pk)
                )
                _expire_locked(locked, now)
        # Finished grants must not stick in the session — otherwise a later Hermes
        # attempt shows "Agent connected" while a new user_code is still pending.
        clear_device_grant(request)
        return render_error(request, 'device_code_expired', 400, user=user)
    if grant.status == McpDeviceAuthorization.STATUS_DENIED:
        clear_device_grant(request)
        return _render_result(request, title=copy['denied'], message='', user=user)
    if grant.status == McpDeviceAuthorization.STATUS_CONSUMED:
        clear_device_grant(request)
        return render_error(request, 'device_code_used', 400, user=user)
    if grant.status == McpDeviceAuthorization.STATUS_APPROVED:
        clear_device_grant(request)
        return _render_result(
            request,
            title=copy['device_approved_title'],
            message=copy['device_approved'],
            user=user,
        )
    if grant.status != McpDeviceAuthorization.STATUS_PENDING:
        clear_device_grant(request)
        return render_error(request, 'device_code_invalid', 400, user=user)
    block = _device_session_block(request, grant)
    if block == 'staff':
        refused = _member_block(request, grant, request.user)
        if refused is not None:
            return refused
    if block:
        return HttpResponseRedirect(reverse('mcp-oauth-signin'))
    from apps.authapi.identity_session import MCP_DEVICE_CONTINUE_KEY, confirmed

    if not confirmed(request, MCP_DEVICE_CONTINUE_KEY, str(grant.id)):
        return _render_device_continue(request, grant)
    return _render_consent(request, grant, request.user)


def complete_pending_device_consent(request: HttpRequest, *, user, company: Company, pending: dict) -> HttpResponse:
    """Finish device approval after global sign-in for the SaaS opt-in."""
    grant_id = str(pending.get('device_grant_id') or '')
    try:
        grant = McpDeviceAuthorization.objects.select_related('client', 'company').get(pk=grant_id)
    except (McpDeviceAuthorization.DoesNotExist, ValueError, ValidationError):
        return render_error(request, 'invalid_request', 400, user=user)
    if grant.company_id != company.id:
        return render_error(request, 'invalid_request', 400, user=user)
    services = list(pending.get('services') or [])
    if pending.get('include_saas') and Agent.SERVICE_SAAS not in services:
        services.append(Agent.SERVICE_SAAS)
    error = _write_approval(
        request,
        user=user,
        grant=grant,
        name=str(pending.get('name') or '')[:255],
        access_mode=str(pending.get('access_mode') or Agent.ACCESS_ASK),
        read_level=str(pending.get('read_level') or Agent.READ_SAFE),
        services=services,
    )
    if error is not None:
        return error
    remember_device_grant(request, str(grant.id))
    return _redirect_device()


@xframe_options_deny
@csrf_protect
@require_http_methods(['GET', 'POST'])
def mcp_device_verification(request: HttpRequest) -> HttpResponse:
    """Browser page at ``verification_uri``. Enter the user code, sign in, then approve or deny."""
    if request.method == 'POST' and str(request.POST.get('account_choice') or '').strip():
        grant = _grant_from_session(request)
        if grant is None:
            return render_error(request, 'invalid_request', 400)
        chosen = _handle_device_account_choice(request, grant)
        if chosen is not None:
            return chosen
        return render_error(request, 'invalid_request', 400)
    if request.method == 'POST' and str(request.POST.get('decision') or '').strip():
        return _post_decision(request)
    if request.method == 'POST':
        return _post_user_code(request)
    prefill_raw = str(request.GET.get('user_code') or '')
    if prefill_raw.strip():
        # New code from Hermes — drop any prior approved grant left in the session.
        clear_device_grant(request)
        return _render_code_form(request, prefill=_safe_prefill(prefill_raw))
    grant = _grant_from_session(request)
    if grant is None:
        return _render_code_form(request, prefill='')
    return _render_grant_state(request, grant)
