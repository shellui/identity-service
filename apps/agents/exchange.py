"""OAuth 2.0 Token Exchange (RFC 8693) for global MCP agent tokens on a regional server."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import F
from django.http import JsonResponse
from django.utils import timezone

from apps.agents.global_revocation import global_agent_exchange_blocked
from apps.agents.mcp_resources import resolve_mcp_resource, resource_company_id
from apps.agents.models import Agent
from apps.agents.scope import (
    access_rank,
    access_within,
    destructive_within,
    is_narrower_or_equal_access,
    is_narrower_or_equal_read,
    is_subset_services,
    parse_services,
    read_rank,
    read_within,
    services_within,
)
from apps.agents.mcp_claims import strict_bool_claim
from apps.agents.tokens import encode_access_token, issue_agent_refresh, revoke_all_agent_refresh_sessions
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
    claims: dict[str, Any],
    *,
    regional_company_id: int,
    global_exp_unix: int | None,
    subject_has_global_binding: bool,
) -> tuple[int | None, datetime | None, bool, int | None]:
    """
    Optional server-authorized new-company setup window from the global subject token.

    Strict booleans: ``setup_flow`` and ``mcp_new_company_grant`` must be JSON true (or string
    ``true`` per ai-service). When ``setup_flow`` is false, setup is cleared. Long setup requires
    ``mcp_new_company_grant``, matching ``setup_context_company_id``, SaaS binding on the subject
    token, numeric ``mcp_session_ttl_seconds`` in the 600 to 900 band, and a valid absolute
    deadline ``setup_expires_at`` not after the global access token ``exp``.
    """
    setup_flow = strict_bool_claim(claims.get('setup_flow'))
    if not setup_flow:
        return None, None, False, None

    new_grant = strict_bool_claim(claims.get('mcp_new_company_grant'))
    try:
        ctx_company = int(claims.get('setup_context_company_id'))
    except (TypeError, ValueError):
        return None, None, False, None
    if ctx_company != regional_company_id:
        return None, None, False, None

    raw_ttl = claims.get('mcp_session_ttl_seconds')
    try:
        setup_ttl = int(raw_ttl)
    except (TypeError, ValueError):
        setup_ttl = 0
    lo = int(getattr(settings, 'MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS', 600) or 600)
    hi = int(getattr(settings, 'MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS', 900) or 900)
    if lo > hi:
        lo, hi = hi, lo

    ctx_exp_unix = None
    raw_setup_deadline = claims.get('setup_expires_at')
    if raw_setup_deadline is not None and raw_setup_deadline != '':
        try:
            ctx_exp_unix = int(raw_setup_deadline)
        except (TypeError, ValueError):
            ctx_exp_unix = None
    else:
        try:
            ctx_exp_unix = int(claims.get('setup_context_exp'))
        except (TypeError, ValueError):
            ctx_exp_unix = None
    try:
        iat = int(claims.get('iat'))
    except (TypeError, ValueError):
        iat = 0
    if ctx_exp_unix is None or ctx_exp_unix <= iat:
        return None, None, False, None

    if global_exp_unix is not None and ctx_exp_unix > int(global_exp_unix):
        return None, None, False, None

    if not new_grant or not subject_has_global_binding:
        return None, None, False, None
    if setup_ttl < lo or setup_ttl > hi:
        return None, None, False, None

    ctx_exp = datetime.fromtimestamp(ctx_exp_unix, tz=dt_timezone.utc)
    return ctx_company, ctx_exp, True, setup_ttl


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


def _merge_regional_exchange_agent(
    *,
    agent: Agent,
    global_access: str,
    global_read: str,
    global_destructive: bool,
    global_cap_services: list[str],
    narrowed_services: list[str],
    existing_services: list[str],
    requested_services: list[str] | None,
    access_from_global: str | None,
    read_from_global: str | None,
    destructive_from_global: bool,
    data: dict[str, Any],
) -> tuple[list[str], str, str, bool, bool] | None:
    """
    Existing regional agent: exchange never widens. Omitted body fields keep the stored row.

    Returns (services, access, read, destructive, did_narrow) or None when the merge is invalid.
    """
    gw_svc = set(narrowed_services)
    ex_set = set(existing_services)

    if requested_services is not None:
        prop_set = gw_svc & ex_set
    else:
        prop_set = ex_set & gw_svc
        if not prop_set:
            return None

    if not prop_set:
        return None
    if not prop_set <= gw_svc:
        return None
    if not prop_set <= ex_set:
        return None

    final_services = sorted(prop_set)
    cap_svc = set(global_cap_services)
    if not set(final_services) <= cap_svc:
        return None

    if data.get('access_mode') not in (None, ''):
        if access_from_global is None:
            return None
        if not is_narrower_or_equal_access(agent.access_mode, access_from_global):
            return None
        final_access = access_from_global
    else:
        final_access = agent.access_mode
    stored_cap = getattr(agent, 'global_max_access_mode', None) or global_access
    if access_within(stored_cap, final_access) is None:
        return None
    if access_within(global_access, final_access) is None:
        return None

    if data.get('read_level') not in (None, ''):
        if read_from_global is None:
            return None
        if not is_narrower_or_equal_read(agent.read_level, read_from_global):
            return None
        final_read = read_from_global
    else:
        final_read = agent.read_level
    stored_read_cap = getattr(agent, 'global_max_read_level', None) or global_read
    if read_within(stored_read_cap, final_read) is None:
        return None
    if read_within(global_read, final_read) is None:
        return None

    if data.get('allow_destructive') not in (None, ''):
        if agent.allow_destructive_without_asking is False and destructive_from_global is True:
            return None
        final_destructive = destructive_from_global
    else:
        final_destructive = bool(agent.allow_destructive_without_asking)
    stored_dest_cap = bool(getattr(agent, 'global_max_destructive', global_destructive))
    if final_destructive and not stored_dest_cap:
        return None
    if final_destructive and not global_destructive:
        return None

    services_narrowed = set(final_services) < ex_set
    access_narrowed = (
        access_rank(final_access) is not None
        and access_rank(agent.access_mode) is not None
        and access_rank(final_access) < access_rank(agent.access_mode)
    )
    read_narrowed = (
        read_rank(final_read) is not None
        and read_rank(agent.read_level) is not None
        and read_rank(final_read) < read_rank(agent.read_level)
    )
    dest_narrowed = agent.allow_destructive_without_asking is True and final_destructive is False
    did_narrow = services_narrowed or access_narrowed or read_narrowed or dest_narrowed

    return final_services, final_access, final_read, final_destructive, did_narrow


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

    global_services_from_claims = parse_services(str(claims.get('scope') or ''))
    claimed_scope_set = set(global_services_from_claims)

    existing_for_cap = (
        Agent.objects.filter(company=company, global_agent_id=global_agent_id)
        .only('global_allowed_services')
        .first()
    )
    stored_global_svc = list(getattr(existing_for_cap, 'global_allowed_services', None) or [])
    if stored_global_svc:
        effective_global_services = sorted(claimed_scope_set & set(stored_global_svc))
        if not effective_global_services:
            return _error('invalid_grant', 'The global agent token would widen allowed services.')
    else:
        effective_global_services = sorted(global_services_from_claims)

    global_cap_services = sorted(effective_global_services)

    requested_services = data.get('services')
    if isinstance(requested_services, str):
        requested_services = [part for part in requested_services.split() if part]
    elif requested_services is not None and not isinstance(requested_services, list):
        requested_services = None
    narrowed_services = services_within(effective_global_services, requested_services)
    if not narrowed_services:
        return _error('invalid_grant', 'Requested services are not allowed for this global agent.')
    if service_id not in claimed_scope_set:
        return _error('invalid_grant', 'The MCP resource is not included in allowed services.')

    global_access = str(claims.get('mcp_access') or Agent.ACCESS_ASK)
    global_read = str(claims.get('mcp_read') or Agent.READ_SAFE)
    global_destructive = bool(claims.get('mcp_destructive'))
    global_access_cap = global_access
    global_read_cap = global_read
    global_destructive_cap = global_destructive
    access_from_global = access_within(global_access, data.get('access_mode'))
    read_from_global = read_within(global_read, data.get('read_level'))
    destructive_from_global = destructive_within(
        global_allowed=global_destructive,
        requested=_parse_optional_bool(data.get('allow_destructive')),
    )
    if access_from_global is None or read_from_global is None:
        return _error('invalid_grant', 'Requested access exceeds the global agent.')
    if destructive_from_global is False and _parse_optional_bool(data.get('allow_destructive')) is True:
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

    try:
        global_exp_unix = int(claims.get('exp'))
    except (TypeError, ValueError):
        global_exp_unix = None

    gid_probe, ver_probe = _parse_global_company_binding(claims)
    subject_has_global_binding = gid_probe is not None and ver_probe is not None

    setup_company_id, setup_expires_at, setup_new_company_flag, setup_ttl_stored = (
        _parse_setup_context_from_global_claims(
            claims,
            regional_company_id=company.pk,
            global_exp_unix=global_exp_unix,
            subject_has_global_binding=subject_has_global_binding,
        )
    )
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
                access_mode=access_from_global,
                read_level=read_from_global,
                allow_destructive_without_asking=destructive_from_global,
                services_allowed=narrowed_services,
                setup_company_id=setup_company_id,
                setup_context_expires_at=setup_expires_at,
                setup_new_company_grant=setup_new_company_flag,
                setup_mcp_session_ttl_seconds=setup_ttl_stored,
                global_company_id=global_company_id,
                company_binding_version=company_binding_version,
                global_allowed_services=global_cap_services,
                global_max_access_mode=global_access_cap,
                global_max_read_level=global_read_cap,
                global_max_destructive=global_destructive_cap,
            )
        else:
            if not agent.is_active:
                return _error('invalid_grant', 'The regional agent is paused, revoked, or expired.')
            if agent.global_company_id and global_company_id and agent.global_company_id != global_company_id:
                return _error('invalid_grant', 'The global company binding does not match this agent.')
            if agent.global_company_id and not global_company_id:
                return _error('invalid_grant', 'The global company binding is missing from the subject token.')
            stored_cap = list(agent.global_allowed_services or [])
            if stored_cap:
                cap_set = set(stored_cap)
                if not set(narrowed_services) <= cap_set:
                    return _error('invalid_grant', 'The global agent token would widen allowed services.')
                cap_access = getattr(agent, 'global_max_access_mode', None) or global_access
                cap_read = getattr(agent, 'global_max_read_level', None) or global_read
                cap_dest = bool(getattr(agent, 'global_max_destructive', global_destructive))
                if (
                    access_rank(global_access) is None
                    or access_rank(cap_access) is None
                    or access_rank(global_access) > access_rank(cap_access)
                ):
                    return _error('invalid_grant', 'The global agent token would widen access mode.')
                if (
                    read_rank(global_read) is None
                    or read_rank(cap_read) is None
                    or read_rank(global_read) > read_rank(cap_read)
                ):
                    return _error('invalid_grant', 'The global agent token would widen read level.')
                if global_destructive and not cap_dest:
                    return _error('invalid_grant', 'The global agent token would widen destructive access.')
            merged = _merge_regional_exchange_agent(
                agent=agent,
                global_access=global_access,
                global_read=global_read,
                global_destructive=global_destructive,
                global_cap_services=global_cap_services,
                narrowed_services=narrowed_services,
                existing_services=list(agent.services_allowed or []),
                requested_services=requested_services,
                access_from_global=access_from_global,
                read_from_global=read_from_global,
                destructive_from_global=destructive_from_global,
                data=data,
            )
            if merged is None:
                return _error('invalid_grant', 'Exchange would widen an existing regional agent.')
            final_services, final_access, final_read, final_destructive, did_narrow = merged
            if global_company_id is not None:
                agent.global_company_id = global_company_id
            if company_binding_version is not None:
                if (
                    agent.company_binding_version is not None
                    and company_binding_version < agent.company_binding_version
                ):
                    return _error('invalid_grant', 'The company binding version is stale.')
                agent.company_binding_version = company_binding_version
            agent.access_mode = final_access
            agent.read_level = final_read
            agent.allow_destructive_without_asking = final_destructive
            agent.services_allowed = final_services
            agent.setup_company_id = setup_company_id
            agent.setup_context_expires_at = setup_expires_at
            agent.setup_new_company_grant = setup_new_company_flag
            agent.setup_mcp_session_ttl_seconds = setup_ttl_stored
            agent.global_max_access_mode = global_access_cap
            agent.global_max_read_level = global_read_cap
            agent.global_max_destructive = global_destructive_cap
            if agent.created_by_id is None:
                agent.created_by = user
            if did_narrow:
                revoke_all_agent_refresh_sessions(agent)
                Agent.objects.filter(pk=agent.pk).update(grant_version=F('grant_version') + 1)
                agent.refresh_from_db(fields=['grant_version'])
            agent.save(
                update_fields=[
                    'access_mode',
                    'read_level',
                    'allow_destructive_without_asking',
                    'services_allowed',
                    'setup_company_id',
                    'setup_context_expires_at',
                    'setup_new_company_grant',
                    'setup_mcp_session_ttl_seconds',
                    'global_company_id',
                    'company_binding_version',
                    'global_max_access_mode',
                    'global_max_read_level',
                    'global_max_destructive',
                    'created_by',
                    'updated_at',
                    'grant_version',
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
