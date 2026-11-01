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
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.clickjacking import xframe_options_deny
from rest_framework import status
from rest_framework.views import APIView
from drf_spectacular.utils import OpenApiResponse, extend_schema

from apps.authapi.client_pkce import PkceError, parse_client_pkce, verify_client_pkce
from apps.authapi.throttling import check_rate_limit
from apps.companies.models import Company
from apps.agents.models import Agent, McpAuthorizationCode, McpOAuthClient
from apps.agents.oauth_codes import hash_authorization_code, issue_mcp_authorization_code
from apps.agents.mcp_resources import resolve_mcp_resource
from apps.agents.oauth_redirect import normalize_mcp_redirect_uris, validate_mcp_redirect_uri
from apps.agents.staff import is_mcp_oauth_refused_user
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
            'grant_types_supported': ['authorization_code', 'refresh_token'],
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
    limited = check_rate_limit(request, scope='oauth')
    if limited:
        return limited
    if not getattr(settings, 'MCP_DYNAMIC_CLIENT_REGISTRATION', True):
        return JsonResponse({'error': 'registration_disabled'}, status=403)
    try:
        body = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'invalid_json'}, status=400)
    redirect_uris, rerr = normalize_mcp_redirect_uris(request, body.get('redirect_uris') or [])
    if rerr:
        return JsonResponse({'error': rerr}, status=400)
    client_id = secrets.token_urlsafe(24)
    row = McpOAuthClient.objects.create(
        client_id=client_id,
        client_name=str(body.get('client_name') or '')[:255],
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
def mcp_authorize(request):
    if request.method not in {'GET', 'POST'}:
        return HttpResponse(status=405)
    limited = check_rate_limit(request, scope='oauth')
    if limited:
        return limited
    response_type = (request.GET.get('response_type') or request.POST.get('response_type') or 'code').strip()
    if response_type != 'code':
        return HttpResponse('Unsupported response_type.', status=400)
    client_id = (request.GET.get('client_id') or request.POST.get('client_id') or '').strip()
    redirect_uri = (request.GET.get('redirect_uri') or request.POST.get('redirect_uri') or '').strip()
    state = (request.GET.get('state') or request.POST.get('state') or '').strip()
    code_challenge = request.GET.get('code_challenge') or request.POST.get('code_challenge')
    code_challenge_method = request.GET.get('code_challenge_method') or request.POST.get('code_challenge_method')
    try:
        challenge = parse_client_pkce(code_challenge, code_challenge_method, required=True)
    except PkceError as exc:
        return HttpResponse(exc.message, status=400)
    try:
        client = McpOAuthClient.objects.get(client_id=client_id)
    except McpOAuthClient.DoesNotExist:
        return HttpResponse('Unknown client.', status=400)
    canonical_redirect, rerr = validate_mcp_redirect_uri(request, redirect_uri)
    if rerr or not canonical_redirect or canonical_redirect not in (client.redirect_uris or []):
        return HttpResponse('Invalid redirect_uri.', status=400)
    redirect_uri = canonical_redirect
    resource_raw = (request.GET.get('resource') or request.POST.get('resource') or '').strip()
    resource_url, _service_id = resolve_mcp_resource(resource_raw)
    if not resource_url:
        return HttpResponse('Invalid or missing resource.', status=400)
    if not request.user.is_authenticated:
        login_url = reverse('admin:login')
        next_url = request.get_full_path()
        return HttpResponseRedirect(f'{login_url}?next={next_url}')
    user = request.user
    if is_mcp_oauth_refused_user(user):
        return HttpResponse('Staff accounts cannot authorize MCP agents.', status=403)
    companies = Company.objects.filter(memberships__user=user, memberships__is_enabled=True).order_by('name')
    if request.method == 'POST':
        return _complete_authorize(
            request,
            user=user,
            client=client,
            redirect_uri=redirect_uri,
            state=state,
            challenge=challenge,
            resource=resource_url,
        )
    return render(
        request,
        'agents/mcp_consent.html',
        {
            'client': client,
            'companies': companies,
            'redirect_uri': redirect_uri,
            'resource': resource_url,
            'state': state,
            'code_challenge': challenge,
            'services': [
                ('identity', 'Identity'),
                ('storage', 'Storage'),
                ('hosting', 'Hosting'),
                ('email', 'Email'),
            ],
        },
    )


def _complete_authorize(request, *, user, client, redirect_uri, state, challenge, resource):
    if request.method != 'POST':
        return HttpResponse('Confirm on the consent form.', status=400)
    company_id = request.POST.get('company_id')
    try:
        company = Company.objects.get(pk=int(company_id))
    except (TypeError, ValueError, Company.DoesNotExist):
        return HttpResponse('Choose a company.', status=400)
    if not company.memberships.filter(user=user, is_enabled=True).exists():
        return HttpResponse('Forbidden for this company.', status=403)
    if not _mcp_company_registration_allowed(company):
        return HttpResponse('Dynamic registration is disabled for this company.', status=403)
    name = (request.POST.get('agent_name') or client.client_name or 'MCP agent')[:255]
    access_mode = request.POST.get('access_mode') or Agent.ACCESS_ASK
    if access_mode not in {Agent.ACCESS_READ_ONLY, Agent.ACCESS_ASK, Agent.ACCESS_FULL}:
        access_mode = Agent.ACCESS_ASK
    read_level = request.POST.get('read_level') or Agent.READ_SAFE
    if read_level not in {Agent.READ_SAFE, Agent.READ_SENSITIVE}:
        read_level = Agent.READ_SAFE
    destructive = request.POST.get('allow_destructive') == 'on'
    services = [s for s in request.POST.getlist('services') if s]
    if not services:
        services = [Agent.SERVICE_IDENTITY]
    allowed_services = {choice[0] for choice in Agent.SERVICE_CHOICES}
    services = [s for s in services if s in allowed_services]
    if not services:
        return HttpResponse('Choose at least one service.', status=400)
    _resource_url, service_id = resolve_mcp_resource(resource)
    if not _resource_url or not service_id or service_id not in services:
        return HttpResponse('Resource is not included in selected services.', status=400)
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
        code_challenge=challenge,
        resource=_resource_url,
        expires_at=timezone.now() + timedelta(minutes=10),
    )
    params = {'code': code}
    if state:
        params['state'] = state
    sep = '&' if '?' in redirect_uri else '?'
    return HttpResponseRedirect(f'{redirect_uri}{sep}{urlencode(params)}')


@csrf_exempt
@require_POST
def mcp_token(request):
    limited = check_rate_limit(request, scope='token_exchange')
    if limited:
        return limited
    try:
        body = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'invalid_json'}, status=400)
    grant = body.get('grant_type')
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
        return JsonResponse({'error': 'unsupported_grant_type'}, status=400)
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
                .select_related('agent', 'user')
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
    access = encode_access_token(agent, resource=bound_resource)
    refresh, _session = issue_agent_refresh(agent, resource=bound_resource)
    return JsonResponse(
        {
            'access_token': access,
            'token_type': 'Bearer',
            'expires_in': int(getattr(settings, 'MCP_ACCESS_TOKEN_LIFETIME', timedelta(minutes=15)).total_seconds()),
            'refresh_token': refresh,
        }
    )
