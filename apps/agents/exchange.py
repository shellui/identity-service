"""OAuth 2.0 Token Exchange (RFC 8693) for global MCP agent tokens on a regional server."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone

from apps.agents.global_revocation import global_agent_exchange_blocked
from apps.agents.mcp_resources import resolve_mcp_resource, resource_company_id
from apps.agents.models import Agent
from apps.agents.scope import (
    access_within,
    destructive_within,
    parse_services,
    read_within,
    services_within,
)
from apps.agents.tokens import encode_access_token, issue_agent_refresh
from apps.authapi.throttling import check_rate_limit
from apps.companies.models import Company
from apps.federation.exchange import ACCESS_TOKEN_TYPE, GRANT_TYPE
from apps.federation.role import is_region
from apps.federation.signing import TokenError, verify_pinned

logger = logging.getLogger(__name__)

GLOBAL_AGENT_TOKEN_TYPE = 'agent_access'


def agent_exchange_enabled() -> bool:
    return bool(
        is_region()
        and (getattr(settings, 'GLOBAL_ISSUER_URL', '') or '').strip()
        and (getattr(settings, 'GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE', '') or '').strip()
        and (getattr(settings, 'GLOBAL_JWKS', {}) or {}).get('keys')
    )


def _error(code: str, description: str, status: int = 400) -> JsonResponse:
    return JsonResponse({'error': code, 'error_description': description}, status=status)


def _staff_refused(claims: dict[str, Any]) -> bool:
    metadata = claims.get('user_metadata') if isinstance(claims.get('user_metadata'), dict) else {}
    if not isinstance(metadata.get('is_staff'), bool) or any(
        source.get(flag) is not False
        for source in (metadata, claims)
        for flag in ('is_staff', 'is_superuser')
        if flag in source
    ):
        return True
    return False


def _consume_subject_jti(jti: str, exp: int) -> bool:
    """Return True when the jti was already used (replay)."""
    now = int(timezone.now().timestamp())
    ttl = max(int(exp) - now, 1)
    return not cache.add(f'agents:exchange-jti:{jti}', 1, timeout=min(ttl, 3600))


def _membership_ok(company: Company, user) -> bool:
    if company.owners.filter(pk=user.pk).exists():
        return True
    return company.memberships.filter(user=user, is_enabled=True).exists()


def _resolve_company(data: dict[str, Any]) -> Company | None:
    try:
        return Company.objects.get(pk=int(str(data.get('company_id') or '').strip()))
    except (Company.DoesNotExist, TypeError, ValueError):
        return None


def _parse_optional_bool(value) -> bool | None:
    if value is None or value == '':
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {'1', 'true', 'yes', 'on'}:
        return True
    if text in {'0', 'false', 'no', 'off'}:
        return False
    return None


def _parse_setup_context_from_global_claims(
    claims: dict[str, Any], *, regional_company_id: int
) -> tuple[int | None, datetime | None]:
    """
    Optional server-authorized new-company setup window from the global subject token.

    Expected (global mint, saas-service): ``setup_flow``, ``setup_context_company_id`` matching
    the regional exchange target, and an absolute deadline as ``setup_expires_at`` (preferred) or
    legacy ``setup_context_exp`` (unix seconds, after ``iat``). Optional ``mcp_session_ttl_seconds``
    (600-900). Identity stores the company id and absolute expiry on the regional ``Agent``; the
    gateway copies ``mcp_session_ttl_seconds`` into approval assertions for session Allow.
    """
    flow = claims.get('setup_flow')
    if isinstance(flow, str):
        flow_ok = flow.strip().lower() in ('1', 'true', 'yes', 'setup', 'setup_flow', 'new_company')
    else:
        flow_ok = bool(flow)
    if not flow_ok:
        return None, None

    try:
        ctx_company = int(claims.get('setup_context_company_id'))
    except (TypeError, ValueError):
        return None, None
    if ctx_company != regional_company_id:
        return None, None

    ctx_exp_unix = None
    raw_setup_deadline = claims.get('setup_expires_at')
    if raw_setup_deadline is not None and raw_setup_deadline != '':
        try:
            ctx_exp_unix = int(raw_setup_deadline)
        except (TypeError, ValueError):
            return None, None
    else:
        try:
            ctx_exp_unix = int(claims.get('setup_context_exp'))
        except (TypeError, ValueError):
            return None, None
    try:
        iat = int(claims.get('iat'))
    except (TypeError, ValueError):
        return None, None
    if ctx_exp_unix is None or ctx_exp_unix <= iat:
        return None, None

    ctx_exp = datetime.fromtimestamp(ctx_exp_unix, tz=dt_timezone.utc)
    return ctx_company, ctx_exp


def _parse_global_company_binding(claims: dict[str, Any]) -> tuple[uuid.UUID | None, int | None]:
    """SaaS-signed global company id and binding generation; both or neither."""
    raw_gid = claims.get('global_company_id')
    raw_ver = claims.get('company_binding_version')
    if raw_gid is None or raw_gid == '':
        return None, None
    try:
        gid = uuid.UUID(str(raw_gid))
    except (TypeError, ValueError):
        return None, None
    if raw_ver is None or raw_ver == '':
        return None, None
    try:
        ver = int(raw_ver)
    except (TypeError, ValueError):
        return None, None
    if ver < 0:
        return None, None
    return gid, ver


def handle_agent_token_exchange(request, *, data: dict[str, Any] | None = None) -> JsonResponse:
    if not agent_exchange_enabled():
        return JsonResponse({}, status=404)
    limited = check_rate_limit(request, scope='token_exchange')
    if limited is not None:
        return limited

    payload = data if data is not None else getattr(request, 'data', {})
    if not isinstance(payload, dict):
        payload = dict(payload)
    data = payload
    if str(data.get('grant_type') or '') != GRANT_TYPE:
        return _error('unsupported_grant_type', 'Grant type is not supported.')
    if str(data.get('subject_token_type') or '') != ACCESS_TOKEN_TYPE:
        return _error('invalid_request', 'subject_token_type must be an access token.')
    requested_type = str(data.get('requested_token_type') or ACCESS_TOKEN_TYPE)
    if requested_type != ACCESS_TOKEN_TYPE:
        return _error('invalid_request', 'Only access tokens can be requested.')
    subject_token = str(data.get('subject_token') or '').strip()
    if not subject_token:
        return _error('invalid_request', 'Missing subject_token.')

    company = _resolve_company(data)
    if company is None:
        return _error('invalid_target', 'Company not found.')

    resource_raw = str(data.get('resource') or '').strip()
    resource_url, service_id = resolve_mcp_resource(resource_raw)
    if not resource_url or not service_id:
        return _error('invalid_target', 'Invalid or unknown MCP resource.')
    resource_company = resource_company_id(resource_url)
    if resource_company is not None and resource_company != company.id:
        return _error('invalid_target', 'The MCP resource belongs to another company.')

    try:
        claims = verify_pinned(
            subject_token,
            audience=settings.GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE,
            issuer_url=settings.GLOBAL_ISSUER_URL,
            require=['exp', 'iat', 'iss', 'aud', 'sub', 'email', 'jti', 'agent_id'],
        )
    except TokenError:
        logger.info('agent token exchange: subject rejected company_id=%s', company.pk)
        return _error('invalid_grant', 'The global agent token is not valid.')

    if claims.get('token_type') != GLOBAL_AGENT_TOKEN_TYPE:
        return _error('invalid_grant', 'The subject token must be a global agent access token.')
    if claims.get('sid') or claims.get('pat_id'):
        return _error('invalid_grant', 'The subject token must be a global agent access token.')
    if claims.get('email_verified') is not True:
        return _error('invalid_grant', 'The email address is not verified on the global server.')
    if _staff_refused(claims):
        logger.info('agent token exchange: global staff refused company_id=%s', company.pk)
        return _error(
            'invalid_grant',
            'Staff accounts cannot use token exchange. Sign in with a local account on this region.',
        )

    try:
        global_agent_id = uuid.UUID(str(claims.get('agent_id')))
    except (TypeError, ValueError):
        return _error('invalid_grant', 'The global agent token is not valid.')
    if global_agent_exchange_blocked(global_agent_id):
        return _error('invalid_grant', 'The global agent is revoked.')

    jti = str(claims.get('jti') or '')
    try:
        exp = int(claims.get('exp'))
    except (TypeError, ValueError):
        return _error('invalid_grant', 'The global agent token is not valid.')
    if not jti or _consume_subject_jti(jti, exp):
        return _error('invalid_grant', 'The global agent token was already used.')

    global_services = parse_services(str(claims.get('scope') or ''))
    requested_services = data.get('services')
    if isinstance(requested_services, str):
        requested_services = [part for part in requested_services.split() if part]
    elif requested_services is not None and not isinstance(requested_services, list):
        requested_services = None
    narrowed_services = services_within(global_services, requested_services)
    if not narrowed_services:
        return _error('invalid_grant', 'Requested services are not allowed for this global agent.')
    if service_id not in narrowed_services:
        return _error('invalid_grant', 'The MCP resource is not included in allowed services.')

    global_access = str(claims.get('mcp_access') or Agent.ACCESS_ASK)
    global_read = str(claims.get('mcp_read') or Agent.READ_SAFE)
    global_destructive = bool(claims.get('mcp_destructive'))
    access_mode = access_within(global_access, data.get('access_mode'))
    read_level = read_within(global_read, data.get('read_level'))
    destructive = destructive_within(
        global_allowed=global_destructive,
        requested=_parse_optional_bool(data.get('allow_destructive')),
    )
    if access_mode is None or read_level is None:
        return _error('invalid_grant', 'Requested access exceeds the global agent.')
    if destructive is False and _parse_optional_bool(data.get('allow_destructive')) is True:
        return _error('invalid_grant', 'Destructive access is not allowed for this global agent.')

    metadata = claims.get('user_metadata') if isinstance(claims.get('user_metadata'), dict) else {}
    link_claims = {
        'iss': claims.get('iss'),
        'sub': claims.get('sub'),
        'email': claims.get('email'),
        'email_verified': True,
        'name': metadata.get('full_name') or metadata.get('name') or '',
    }
    from apps.federation.relying import link_verified_user

    user, link_error = link_verified_user(link_claims)
    if link_error or user is None:
        return _error('invalid_grant', link_error or 'access_denied')
    if not _membership_ok(company, user):
        return _error('invalid_grant', 'You are not a member of this company in this region.')

    agent_name = str(claims.get('agent_name') or claims.get('name') or 'Global agent')[:255]

    setup_company_id, setup_expires_at = _parse_setup_context_from_global_claims(claims, regional_company_id=company.pk)
    global_company_id, company_binding_version = _parse_global_company_binding(claims)

    with transaction.atomic():
        agent = (
            Agent.objects.select_for_update()
            .filter(company=company, global_agent_id=global_agent_id)
            .first()
        )
        if agent is None:
            agent = Agent.objects.create(
                company=company,
                global_agent_id=global_agent_id,
                name=agent_name,
                created_by=user,
                access_mode=access_mode,
                read_level=read_level,
                allow_destructive_without_asking=destructive,
                services_allowed=narrowed_services,
                setup_company_id=setup_company_id,
                setup_context_expires_at=setup_expires_at,
                global_company_id=global_company_id,
                company_binding_version=company_binding_version,
            )
        else:
            if not agent.is_active:
                return _error('invalid_grant', 'The regional agent is paused, revoked, or expired.')
            if agent.global_company_id and global_company_id and agent.global_company_id != global_company_id:
                return _error('invalid_grant', 'The global company binding does not match this agent.')
            if agent.global_company_id and not global_company_id:
                return _error('invalid_grant', 'The global company binding is missing from the subject token.')
            if global_company_id is not None:
                agent.global_company_id = global_company_id
            if company_binding_version is not None:
                if (
                    agent.company_binding_version is not None
                    and company_binding_version < agent.company_binding_version
                ):
                    return _error('invalid_grant', 'The company binding version is stale.')
                agent.company_binding_version = company_binding_version
            agent.access_mode = access_mode
            agent.read_level = read_level
            agent.allow_destructive_without_asking = destructive
            agent.services_allowed = narrowed_services
            agent.setup_company_id = setup_company_id
            agent.setup_context_expires_at = setup_expires_at
            if agent.created_by_id is None:
                agent.created_by = user
            agent.save(
                update_fields=[
                    'access_mode',
                    'read_level',
                    'allow_destructive_without_asking',
                    'services_allowed',
                    'setup_company_id',
                    'setup_context_expires_at',
                    'global_company_id',
                    'company_binding_version',
                    'created_by',
                    'updated_at',
                ]
            )

    access = encode_access_token(agent, resource=resource_url)
    refresh, _session = issue_agent_refresh(agent, resource=resource_url)
    logger.info(
        'agent token exchange: issued company_id=%s agent_id=%s global_agent_id=%s',
        company.pk,
        agent.pk,
        global_agent_id,
    )
    return JsonResponse(
        {
            'access_token': access,
            'issued_token_type': ACCESS_TOKEN_TYPE,
            'token_type': 'Bearer',
            'expires_in': int(
                getattr(settings, 'MCP_ACCESS_TOKEN_LIFETIME', timedelta(minutes=15)).total_seconds()
            ),
            'refresh_token': refresh,
        },
        headers={'Cache-Control': 'no-store', 'Pragma': 'no-cache'},
    )
