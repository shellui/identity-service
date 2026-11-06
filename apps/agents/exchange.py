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
from apps.agents.json_strict import strict_non_negative_int, strict_positive_company_id_for_oauth_form
from apps.agents.mcp_resources import (
    GATEWAY_SERVICE_ID,
    is_regional_gateway_resource_for_company,
    resolve_mcp_resource,
    resource_company_id,
)
from apps.agents.models import Agent
from apps.agents.scope import (
    access_rank,
    access_within,
    destructive_within,
    is_narrower_or_equal_access,
    is_narrower_or_equal_read,
    parse_regional_mcp_scope,
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
# Global issuer (SaaS) profile for MCP agents that may exchange to a regional delegated row.
GLOBAL_AGENT_MCP_AUTHORITY = 'global_delegated'


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
    """Reject only explicit ``True`` staff; any other type than JSON false is invalid."""
    metadata = claims.get('user_metadata') if isinstance(claims.get('user_metadata'), dict) else {}
    for source in (metadata, claims):
        for flag in ('is_staff', 'is_superuser'):
            if flag not in source:
                continue
            val = source.get(flag)
            if val is True:
                return True
            if val is not False:
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
    cid = strict_positive_company_id_for_oauth_form(data.get('company_id'))
    if cid is None:
        return None
    try:
        return Company.objects.get(pk=cid)
    except Company.DoesNotExist:
        return None


def _parse_optional_bool(value) -> bool | None:
    if value is None or value == '':
        return None
    if value is True:
        return True
    if value is False:
        return False
    return None


def _parse_setup_context_from_global_claims(
    claims: dict[str, Any],
    *,
    regional_company_id: int,
    global_exp_unix: int | None,
    subject_has_global_binding: bool,
) -> tuple[int | None, datetime | None, bool, int | None, str | None]:
    """
    Optional new-company setup from the global subject token (global issuer, SaaS-signed).

    When ``setup_flow`` is absent and ``mcp_new_company_grant`` is absent, setup is cleared.

    When ``setup_flow`` is JSON ``false``, setup is cleared; ``mcp_new_company_grant`` must not appear.

    When ``setup_flow`` is JSON ``true``, require ``mcp_new_company_grant`` JSON ``true`` (no string or
    numeric truthiness), plus the usual setup fields, or the exchange is rejected.
    """
    if 'setup_context_exp' in claims:
        return None, None, False, None, 'Legacy setup_context_exp is not accepted on global subject tokens.'

    has_sf = 'setup_flow' in claims
    has_grant_claim = 'mcp_new_company_grant' in claims

    if not has_sf:
        if has_grant_claim:
            return None, None, False, None, 'mcp_new_company_grant requires setup_flow on the global subject token.'
        return None, None, False, None, None

    sf_raw = claims.get('setup_flow')
    if sf_raw is not True and sf_raw is not False:
        return None, None, False, None, 'setup_flow must be JSON true or false on the global subject token.'
    if sf_raw is False:
        if has_grant_claim:
            return None, None, False, None, 'mcp_new_company_grant must not appear when setup_flow is false.'
        return None, None, False, None, None

    # setup_flow is JSON true
    grant_raw = claims.get('mcp_new_company_grant')
    if not strict_bool_claim(grant_raw):
        return (
            None,
            None,
            False,
            None,
            'mcp_new_company_grant must be JSON true when setup_flow is true on the global subject token.',
        )

    raw_ctx = claims.get('setup_context_company_id')
    ctx_co = strict_non_negative_int(raw_ctx)
    if ctx_co is None or ctx_co == 0:
        return None, None, False, None, 'setup_context_company_id must be a positive JSON integer.'
    ctx_company = ctx_co
    if ctx_company != regional_company_id:
        return None, None, False, None, 'setup_context_company_id does not match token exchange company.'

    raw_deadline = claims.get('setup_expires_at')
    ctx_exp_unix = strict_non_negative_int(raw_deadline)
    if ctx_exp_unix is None:
        return None, None, False, None, 'setup_expires_at is required when setup_flow is true.'
    iat_raw = claims.get('iat')
    iat_val = strict_non_negative_int(iat_raw)
    if iat_val is None:
        return None, None, False, None, 'Invalid iat on global subject token.'
    iat = iat_val
    if ctx_exp_unix <= iat:
        return None, None, False, None, 'setup_expires_at must be after iat.'
    if global_exp_unix is not None and ctx_exp_unix > int(global_exp_unix):
        return None, None, False, None, 'setup_expires_at must not be after global exp.'
    now_ts = int(timezone.now().timestamp())
    if ctx_exp_unix <= now_ts:
        return None, None, False, None, 'setup_expires_at is in the past.'

    raw_ttl = claims.get('mcp_session_ttl_seconds')
    setup_ttl = strict_non_negative_int(raw_ttl)
    if setup_ttl is None:
        return None, None, False, None, 'mcp_session_ttl_seconds must be an integer when setup_flow is true.'
    lo = int(getattr(settings, 'MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS', 600) or 600)
    hi = int(getattr(settings, 'MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS', 900) or 900)
    if lo > hi:
        lo, hi = hi, lo
    if setup_ttl < lo or setup_ttl > hi:
        return None, None, False, None, 'mcp_session_ttl_seconds must be within the setup band.'

    if not subject_has_global_binding:
        return None, None, False, None, 'setup_flow requires global_company_id and company_binding_version.'

    ctx_exp = datetime.fromtimestamp(ctx_exp_unix, tz=dt_timezone.utc)
    return ctx_company, ctx_exp, True, setup_ttl, None


def _parse_delegated_global_binding(claims: dict[str, Any]) -> tuple[uuid.UUID, int] | None:
    """
    Strict SaaS binding for delegated global agent exchange.

    Both claims must be present with concrete types: UUID string for ``global_company_id``,
    non-negative int for ``company_binding_version`` (``0`` is valid). Anything else rejects exchange.
    """
    if 'global_company_id' not in claims or 'company_binding_version' not in claims:
        return None
    raw_gid = claims.get('global_company_id')
    raw_ver = claims.get('company_binding_version')
    if not isinstance(raw_gid, str) or raw_gid.strip() == '':
        return None
    if isinstance(raw_ver, bool):
        return None
    try:
        gid = uuid.UUID(raw_gid.strip())
    except (TypeError, ValueError, AttributeError):
        return None
    if type(raw_ver) is not int:
        return None
    ver = raw_ver
    if ver < 0:
        return None
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
    _ad = data.get('allow_destructive')
    if _ad is not None and not isinstance(_ad, bool):
        return _error('invalid_grant', 'allow_destructive must be a JSON boolean when present.')
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
    if not is_regional_gateway_resource_for_company(resource_raw, company.pk):
        return _error(
            'invalid_target',
            'Delegated token exchange requires the regional AI gateway resource for this company.',
        )
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
    if claims.get('mcp_authority') != GLOBAL_AGENT_MCP_AUTHORITY:
        return _error('invalid_grant', 'The global agent token must declare mcp_authority global_delegated.')
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

    binding = _parse_delegated_global_binding(claims)
    if binding is None:
        return _error(
            'invalid_grant',
            'Delegated global agent token must include valid global_company_id and company_binding_version.',
        )
    global_company_id, company_binding_version = binding
    subject_has_global_binding = True

    raw_scope = claims.get('scope')
    if raw_scope is None or raw_scope == '':
        return _error('invalid_grant', 'The global agent token scope is missing.')
    global_services_from_claims = parse_regional_mcp_scope(str(raw_scope))
    if not global_services_from_claims:
        return _error(
            'invalid_grant',
            'The global agent scope must include at least one regional MCP service id.',
        )
    claimed_scope_set = set(global_services_from_claims)

    existing_for_cap = (
        Agent.objects.filter(company=company, global_agent_id=global_agent_id)
        .only('global_allowed_services', 'services_allowed')
        .first()
    )
    stored_global_svc = list(getattr(existing_for_cap, 'global_allowed_services', None) or [])
    if existing_for_cap is not None:
        if not stored_global_svc:
            return _error('invalid_grant', 'The regional agent has no stored service cap.')
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
    if requested_services is None and existing_for_cap is not None:
        existing_regional = list(getattr(existing_for_cap, 'services_allowed', None) or [])
        intersection = sorted(set(effective_global_services) & set(existing_regional))
        if not intersection:
            return _error(
                'invalid_grant',
                'Omitted services must stay within the regional agent allowed set.',
            )
        narrowed_services = intersection
    else:
        narrowed_services = services_within(effective_global_services, requested_services)
    if not narrowed_services:
        return _error('invalid_grant', 'Requested services are not allowed for this global agent.')
    if service_id == GATEWAY_SERVICE_ID and GATEWAY_SERVICE_ID not in claimed_scope_set:
        return _error(
            'invalid_grant',
            'The global agent scope must include the ai service for the regional AI gateway resource.',
        )
    if service_id not in claimed_scope_set:
        return _error('invalid_grant', 'The MCP resource is not included in allowed services.')

    try:
        global_mcp_access = str(claims.get('mcp_access'))
    except (TypeError, ValueError):
        return _error('invalid_grant', 'mcp_access is required on the global subject token.')
    try:
        global_mcp_read = str(claims.get('mcp_read'))
    except (TypeError, ValueError):
        return _error('invalid_grant', 'mcp_read is required on the global subject token.')
    raw_dest = claims.get('mcp_destructive')
    if raw_dest is True:
        global_destructive = True
    elif raw_dest is False:
        global_destructive = False
    else:
        return _error('invalid_grant', 'mcp_destructive must be a boolean on the global subject token.')
    global_access = global_mcp_access
    global_read = global_mcp_read
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

    setup_company_id: int | None = None
    setup_expires_at: datetime | None = None
    setup_new_company_flag = False
    setup_ttl_stored: int | None = None
    setup_company_id, setup_expires_at, setup_new_company_flag, setup_ttl_stored, setup_parse_err = (
        _parse_setup_context_from_global_claims(
            claims,
            regional_company_id=company.pk,
            global_exp_unix=global_exp_unix,
            subject_has_global_binding=subject_has_global_binding,
        )
    )
    if setup_parse_err:
        return _error('invalid_grant', setup_parse_err)
    clear_setup = not setup_new_company_flag

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
                allow_destructive_without_asking=False,
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
            if agent.global_company_id is None:
                # First SaaS company bind for an older regional row that only had global_agent_id.
                pass
            elif agent.global_company_id != global_company_id:
                return _error('invalid_grant', 'The global company binding does not match this agent.')
            if (
                agent.global_company_id is not None
                and agent.company_binding_version is not None
                and company_binding_version < agent.company_binding_version
            ):
                return _error('invalid_grant', 'The company binding version is stale.')
            stored_cap = list(agent.global_allowed_services or [])
            if not stored_cap:
                return _error('invalid_grant', 'The regional agent has no stored service cap.')
            cap_set = set(stored_cap)
            if not set(narrowed_services) <= cap_set:
                return _error('invalid_grant', 'The global agent token would widen allowed services.')
            cap_access = getattr(agent, 'global_max_access_mode', None)
            cap_read = getattr(agent, 'global_max_read_level', None)
            cap_dest = getattr(agent, 'global_max_destructive', None)
            if cap_access is None or cap_read is None or cap_dest is None:
                return _error('invalid_grant', 'The regional agent is missing stored global caps.')
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
            if global_destructive and not bool(cap_dest):
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

            prev_acc = getattr(agent, 'global_max_access_mode', None)
            prev_read = getattr(agent, 'global_max_read_level', None)
            if prev_acc is None or prev_read is None:
                return _error('invalid_grant', 'The regional agent is missing stored global caps.')
            r_g = access_rank(global_access)
            r_pa = access_rank(prev_acc)
            r_gr = read_rank(global_read)
            r_pr = read_rank(prev_read)
            if r_g is None or r_pa is None or r_gr is None or r_pr is None:
                return _error('invalid_grant', 'Invalid global access or read on subject token.')
            agent.global_max_access_mode = global_access if r_g < r_pa else prev_acc
            agent.global_max_read_level = global_read if r_gr < r_pr else prev_read
            prev_dest = bool(getattr(agent, 'global_max_destructive', False))
            agent.global_max_destructive = prev_dest and global_destructive

            agent.global_allowed_services = global_cap_services
            agent.global_company_id = global_company_id
            agent.company_binding_version = company_binding_version
            agent.access_mode = final_access
            agent.read_level = final_read
            agent.allow_destructive_without_asking = False
            agent.services_allowed = final_services
            agent.setup_company_id = setup_company_id
            agent.setup_context_expires_at = setup_expires_at
            agent.setup_new_company_grant = setup_new_company_flag
            agent.setup_mcp_session_ttl_seconds = setup_ttl_stored
            if clear_setup:
                agent.setup_company_id = None
                agent.setup_context_expires_at = None
                agent.setup_new_company_grant = False
                agent.setup_mcp_session_ttl_seconds = None
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
                    'global_allowed_services',
                    'global_max_access_mode',
                    'global_max_read_level',
                    'global_max_destructive',
                    'created_by',
                    'updated_at',
                    'grant_version',
                ]
            )

    try:
        access = encode_access_token(agent, resource=resource_url)
    except ValueError as exc:
        return _error('invalid_grant', str(exc) or 'The agent cannot issue tokens.')
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
