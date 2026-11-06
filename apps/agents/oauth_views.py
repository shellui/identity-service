"""MCP OAuth authorization server (authorization code + PKCE, dynamic client registration)."""

from __future__ import annotations

import json
import secrets
from datetime import timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import login
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.db import transaction
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.clickjacking import xframe_options_deny
from rest_framework import status
from rest_framework.views import APIView
from drf_spectacular.utils import OpenApiResponse, extend_schema

from apps.authapi.client_pkce import PkceError, parse_client_pkce, verify_client_pkce
from apps.authapi.throttling import check_rate_limit
from apps.companies.models import Company
from apps.agents.models import Agent, McpAuthorizationCode, McpCallLog, McpOAuthClient
from apps.agents.oauth_codes import hash_authorization_code, issue_mcp_authorization_code
from apps.agents.mcp_resources import resolve_mcp_resource
from apps.agents.oauth_redirect import normalize_mcp_redirect_uris, validate_mcp_redirect_uri
from apps.agents.oauth_request_body import oauth_error, parse_oauth_post_body, redirect_uris_from_body
from apps.agents.mcp_copy import copy_for
from apps.agents.mcp_signin import (
    AuthorizeError,
    approval_redirect,
    is_company_member,
    page_language,
    parse_authorize_request,
    plain_response,
    protect_page,
    render_error,
    render_message,
    safe_authorize_path,
    signin_redirect,
)
from apps.agents.staff import is_mcp_oauth_refused_user
from apps.agents.exchange import GRANT_TYPE as AGENT_EXCHANGE_GRANT
from apps.agents.exchange import agent_exchange_enabled, handle_agent_token_exchange
from apps.agents.tokens import encode_access_token, issue_agent_refresh, refresh_agent_access
from apps.authapi.serializers import ShellUIOpenAPISerializer


def _issuer() -> str:
    return (getattr(settings, 'JWT_ISSUER', '') or '').rstrip('/')


def _mcp_company_registration_allowed(company: Company | None) -> bool:
    if not getattr(settings, 'MCP_DYNAMIC_CLIENT_REGISTRATION', True):
        return False
    if company is None:
        return True
    return bool(getattr(company, 'mcp_allow_dynamic_registration', True))


class OAuthAuthorizationServerMetadataView(APIView):
    authentication_classes = []
    permission_classes = []
    serializer_class = ShellUIOpenAPISerializer

    @extend_schema(
        tags=['.well-known'],
        responses={200: OpenApiResponse(description='OAuth authorization server metadata JSON')},
        auth=[],
    )
    def get(self, request):
        base = _issuer() or request.build_absolute_uri('/').rstrip('/')
        data = {
            'issuer': base,
            'authorization_endpoint': f'{base}/oauth/mcp/authorize',
            'token_endpoint': f'{base}/oauth/mcp/token',
            'registration_endpoint': f'{base}/oauth/mcp/register',
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code', 'refresh_token', AGENT_EXCHANGE_GRANT],
            'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': ['none'],
            'scopes_supported': ['mcp'],
            'resource_indicators_supported': True,
        }
        return JsonResponse(data)


class OAuthProtectedResourceMetadataView(APIView):
    authentication_classes = []
    permission_classes = []
    serializer_class = ShellUIOpenAPISerializer

    @extend_schema(
        tags=['.well-known'],
        responses={200: OpenApiResponse(description='OAuth protected resource metadata JSON')},
        auth=[],
    )
    def get(self, request):
        base = _issuer() or request.build_absolute_uri('/').rstrip('/')
        return JsonResponse(
            {
                'resource': f'{base}/mcp',
                'authorization_servers': [base],
                'bearer_methods_supported': ['header'],
            }
        )


@csrf_exempt
@require_POST
def mcp_register(request):
    limited = plain_response(check_rate_limit(request, scope='mcp_register'))
    if limited:
        return limited
    if not getattr(settings, 'MCP_DYNAMIC_CLIENT_REGISTRATION', True):
        return JsonResponse({'error': 'registration_disabled'}, status=403)
    body, parse_err = parse_oauth_post_body(request)
    if parse_err is not None:
        return parse_err
    assert body is not None
    redirect_uris, rerr = normalize_mcp_redirect_uris(request, redirect_uris_from_body(body))
    if rerr:
        return JsonResponse({'error': rerr}, status=400)
    client_id = secrets.token_urlsafe(24)
    row = McpOAuthClient.objects.create(
        client_id=client_id,
        client_name=' '.join(str(body.get('client_name') or '').split())[:120],
        redirect_uris=redirect_uris,
    )
    return JsonResponse(
        {
            'client_id': row.client_id,
            'client_id_issued_at': int(row.created_at.timestamp()),
            'redirect_uris': row.redirect_uris,
            'token_endpoint_auth_method': 'none',
        },
        status=201,
    )


@xframe_options_deny
@csrf_protect
def mcp_authorize(request):
    """Authorize an MCP client for the company in the per-company resource.

    Every invalid client, redirect_uri, or resource gets an error page on identity. This view
    only ever redirects to identity's own sign-in page or to a redirect_uri the client
    registered, matched exactly.
    """
    if request.method not in {'GET', 'POST'}:
        return HttpResponse(status=405)
    limited = plain_response(check_rate_limit(request, scope='oauth'))
    if limited:
        return limited
    params = request.GET if request.method == 'GET' else request.POST
    try:
        parsed = parse_authorize_request(params)
    except AuthorizeError as exc:
        return render_error(request, exc.code, exc.status)
    from apps.agents.mcp_saas_consent import remember_saas_offered_from_params

    remember_saas_offered_from_params(request, params)
    if not request.user.is_authenticated:
        if request.method != 'GET':
            return render_error(request, 'invalid_request', 400)
        path = safe_authorize_path(request.get_full_path())
        if not path:
            return render_error(request, 'invalid_request', 400)
        return signin_redirect(request, path, parsed.company_id)
    user = request.user
    lang = page_language(request, user)
    copy = copy_for(lang)
    if is_mcp_oauth_refused_user(user):
        return render_message(request, copy['staff_refused'], 403, user=user)
    if parsed.company is None:
        return render_error(request, 'unknown_company', 404, user=user)
    if not _mcp_company_registration_allowed(parsed.company):
        return render_error(request, 'registration_disabled', 403, user=user)
    if not is_company_member(parsed.company, user):
        return render_message(request, copy['not_member'].format(company=parsed.company.name), 403, user=user)
    if request.method == 'POST':
        return _complete_authorize(request, user=user, parsed=parsed)
    client_name = parsed.client.client_name or parsed.client.client_id
    services = [
        (sid, label)
        for sid, label in Agent.SERVICE_CHOICES
        if sid not in {Agent.SERVICE_AI, Agent.SERVICE_SAAS}
    ]
    from apps.agents.mcp_saas_consent import saas_opt_in_offered

    response = render(
        request,
        'agents/mcp_consent.html',
        {
            'page_language': lang,
            'copy': copy,
            'consent_title': copy['consent_title'].format(client_name=client_name),
            'consent_body': copy['consent_body'].format(
                client_name=client_name, company_name=parsed.company.name
            ),
            'phishing': copy['phishing'].format(client_name=client_name),
            'signed_in_as': copy['signed_in_as'].format(email=user.email or user.get_username()),
            'client_name': client_name,
            'client_id': parsed.client.client_id,
            'company_name': parsed.company.name,
            'redirect_host': parsed.redirect_host,
            'redirect_uri': parsed.redirect_uri,
            'resource': parsed.resource,
            'state': parsed.state,
            'code_challenge': parsed.challenge,
            'services': services,
            'saas_opt_in_offered': saas_opt_in_offered(request),
        },
    )
    return protect_page(response)


def _finalize_authorization(
    request,
    *,
    user,
    parsed,
    name: str,
    access_mode: str,
    read_level: str,
    destructive: bool,
    services: list[str],
):
    client = parsed.client
    company = parsed.company
    redirect_uri = parsed.redirect_uri
    if parsed.service_id not in services:
        services = [*services, parsed.service_id]
    with transaction.atomic():
        agent = Agent.objects.create(
            company=company,
            name=name,
            oauth_client=client,
            created_by=user,
            access_mode=access_mode,
            allow_destructive_without_asking=destructive,
            read_level=read_level,
            services_allowed=services,
        )
        code, code_digest = issue_mcp_authorization_code()
        McpAuthorizationCode.objects.create(
            code=code_digest,
            client=client,
            user=user,
            company=company,
            agent=agent,
            redirect_uri=redirect_uri,
            code_challenge=parsed.challenge,
            resource=parsed.resource,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        McpCallLog.objects.create(
            agent=agent,
            company=company,
            service='identity',
            tool='oauth.authorize.approved',
            http_method='POST',
            path='/oauth/mcp/authorize',
            status_code=302,
            arguments_redacted={
                'client_id': client.client_id,
                'client_name': client.client_name[:255],
                'redirect_host': parsed.redirect_host,
                'resource': parsed.resource,
                'services': services,
                'access_mode': access_mode,
                'read_level': read_level,
                'allow_destructive': destructive,
                'approved_by_user_id': user.pk,
            },
        )
    params = {'code': code}
    if parsed.state:
        params['state'] = parsed.state
    return approval_redirect(redirect_uri, params)


def complete_pending_mcp_consent(request, *, user, company, pending: dict):
    from apps.agents.mcp_signin import parse_authorize_request, safe_authorize_path
    from urllib.parse import parse_qs, urlsplit

    path = safe_authorize_path(pending.get('authorize_path'))
    if not path:
        return render_error(request, 'invalid_request', 400)
    try:
        parsed = parse_authorize_request(parse_qs(urlsplit(path).query))
    except AuthorizeError:
        return render_error(request, 'invalid_request', 400)
    if parsed.company is None or parsed.company.id != company.id:
        return render_error(request, 'invalid_request', 400)
    services = list(pending.get('services') or [])
    if pending.get('include_saas') and Agent.SERVICE_SAAS not in services:
        services.append(Agent.SERVICE_SAAS)
    return _finalize_authorization(
        request,
        user=user,
        parsed=parsed,
        name=str(pending.get('name') or '')[:255],
        access_mode=pending.get('access_mode') or Agent.ACCESS_ASK,
        read_level=pending.get('read_level') or Agent.READ_SAFE,
        destructive=bool(pending.get('destructive')),
        services=services,
    )


def _complete_authorize(request, *, user, parsed):
    client = parsed.client
    company = parsed.company
    redirect_uri = parsed.redirect_uri
    decision = request.POST.get('decision')
    if decision == 'deny':
        params = {'error': 'access_denied'}
        if parsed.state:
            params['state'] = parsed.state
        return approval_redirect(redirect_uri, params)
    if decision != 'approve':
        return render_error(request, 'invalid_request', 400)
    name = (request.POST.get('agent_name') or client.client_name or 'MCP agent')[:255]
    access_mode = request.POST.get('access_mode') or Agent.ACCESS_ASK
    if access_mode not in {Agent.ACCESS_READ_ONLY, Agent.ACCESS_ASK, Agent.ACCESS_FULL}:
        access_mode = Agent.ACCESS_ASK
    read_level = request.POST.get('read_level') or Agent.READ_SAFE
    if read_level not in {Agent.READ_SAFE, Agent.READ_SENSITIVE}:
        read_level = Agent.READ_SAFE
    destructive = request.POST.get('allow_destructive') == 'on'
    allowed_services = {choice[0] for choice in Agent.SERVICE_CHOICES}
    services = [s for s in request.POST.getlist('services') if s in allowed_services and s != Agent.SERVICE_AI]
    if not services:
        return render_error(request, 'invalid_request', 400)
    include_saas = request.POST.get('include_saas') == 'on'
    from apps.agents.mcp_saas_consent import (
        saas_opt_in_offered,
        saas_opt_in_requires_global_signin,
        start_global_identity_signin,
        store_pending_consent,
    )
    from apps.agents.exchange import agent_exchange_enabled

    if include_saas and saas_opt_in_offered(request):
        if is_mcp_oauth_refused_user(user):
            return render_message(request, copy_for(page_language(request, user))['staff_refused'], 403, user=user)
        if agent_exchange_enabled() and saas_opt_in_requires_global_signin(include_saas=True, request=request):
            from apps.agents.mcp_signin import build_authorize_path

            store_pending_consent(
                request,
                {
                    'authorize_path': build_authorize_path(parsed, saas_offered=True),
                    'name': name,
                    'access_mode': access_mode,
                    'read_level': read_level,
                    'destructive': destructive,
                    'services': services,
                    'include_saas': True,
                },
            )
            return start_global_identity_signin(request, company_id=company.id)
        if Agent.SERVICE_SAAS not in services:
            services.append(Agent.SERVICE_SAAS)
    return _finalize_authorization(
        request,
        user=user,
        parsed=parsed,
        name=name,
        access_mode=access_mode,
        read_level=read_level,
        destructive=destructive,
        services=services,
    )


@csrf_exempt
@require_POST
def mcp_token(request):
    limited = plain_response(check_rate_limit(request, scope='token_exchange'))
    if limited:
        return limited
    body, parse_err = parse_oauth_post_body(request)
    if parse_err is not None:
        return parse_err
    assert body is not None
    grant = str(body.get('grant_type') or '').strip()
    if not grant:
        return oauth_error('invalid_request')
    if grant == AGENT_EXCHANGE_GRANT:
        if not agent_exchange_enabled():
            return JsonResponse({}, status=404)
        return handle_agent_token_exchange(request, data=body)
    if grant == 'refresh_token':
        refresh = str(body.get('refresh_token') or '')
        resource_url, _service_id = resolve_mcp_resource(str(body.get('resource') or ''))
        if not resource_url:
            return JsonResponse({'error': 'invalid_target'}, status=400)
        pair = refresh_agent_access(refresh, resource=resource_url)
        if not pair:
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        access, new_refresh = pair
        return JsonResponse(
            {
                'access_token': access,
                'token_type': 'Bearer',
                'expires_in': int(getattr(settings, 'MCP_ACCESS_TOKEN_LIFETIME', timedelta(minutes=15)).total_seconds()),
                'refresh_token': new_refresh,
            }
        )
    if grant != 'authorization_code':
        return oauth_error('unsupported_grant_type')
    code = str(body.get('code') or '').strip()
    redirect_uri = str(body.get('redirect_uri') or '').strip()
    client_id = str(body.get('client_id') or '').strip()
    verifier = body.get('code_verifier')
    try:
        client = McpOAuthClient.objects.get(client_id=client_id)
    except McpOAuthClient.DoesNotExist:
        return JsonResponse({'error': 'invalid_client'}, status=401)
    code_digest = hash_authorization_code(code)
    canonical_redirect, rerr = validate_mcp_redirect_uri(request, redirect_uri)
    if rerr or not canonical_redirect:
        return JsonResponse({'error': 'invalid_grant'}, status=400)
    redirect_uri = canonical_redirect
    with transaction.atomic():
        try:
            row = (
                McpAuthorizationCode.objects.select_for_update()
                .select_related('agent__company', 'user')
                .get(code=code_digest, client=client)
            )
        except McpAuthorizationCode.DoesNotExist:
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        if row.redeemed_at is not None or row.expires_at <= timezone.now():
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        if row.redirect_uri != redirect_uri:
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        agent = row.agent
        resource_url, service_id = resolve_mcp_resource(str(body.get('resource') or ''))
        if not resource_url or row.resource != resource_url:
            return JsonResponse({'error': 'invalid_target'}, status=400)
        if not service_id or service_id not in (agent.services_allowed or []):
            return JsonResponse({'error': 'access_denied'}, status=403)
        message, _code = verify_client_pkce(
            code_challenge=row.code_challenge,
            code_verifier=verifier,
            required=True,
        )
        if message:
            return JsonResponse({'error': 'invalid_grant', 'error_description': message}, status=400)
        if is_mcp_oauth_refused_user(row.user):
            return JsonResponse({'error': 'access_denied'}, status=403)
        if not agent.is_active:
            return JsonResponse({'error': 'access_denied'}, status=403)
        row.redeemed_at = timezone.now()
        row.save(update_fields=['redeemed_at'])
        bound_resource = row.resource
    try:
        access = encode_access_token(agent, resource=bound_resource)
    except ValueError:
        return JsonResponse({'error': 'invalid_grant'}, status=400)
    refresh, _session = issue_agent_refresh(agent, resource=bound_resource)
    return JsonResponse(
        {
            'access_token': access,
            'token_type': 'Bearer',
            'expires_in': int(getattr(settings, 'MCP_ACCESS_TOKEN_LIFETIME', timedelta(minutes=15)).total_seconds()),
            'refresh_token': refresh,
        }
    )
