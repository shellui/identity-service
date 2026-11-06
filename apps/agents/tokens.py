"""JWT access and refresh tokens for MCP agents."""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.agents.global_revocation import global_agent_exchange_blocked
from apps.agents.models import Agent, AgentRefreshSession
from apps.agents.mcp_resources import normalize_mcp_resource as normalize_resource_indicator
from apps.agents.mcp_resources import resource_company_id
from apps.agents.scope import (
    access_rank,
    is_subset_services,
    read_rank,
)


def mcp_access_lifetime() -> timedelta:
    return getattr(settings, 'MCP_ACCESS_TOKEN_LIFETIME', timedelta(minutes=15))


def mcp_refresh_lifetime() -> timedelta:
    return getattr(settings, 'MCP_REFRESH_TOKEN_LIFETIME', timedelta(days=30))


def agent_services_scope(agent: Agent) -> str:
    services = agent.services_allowed or []
    return ' '.join(str(s) for s in services)


def company_name_for_agent(agent: Agent) -> str:
    if not agent.company_id:
        return ''
    if 'company' in agent._state.fields_cache:
        return agent.company.name or ''
    from apps.companies.models import Company

    name = Company.objects.filter(pk=agent.company_id).values_list('name', flat=True).first()
    return name or ''


def build_agent_access_token(agent: Agent, *, resource: str) -> dict:
    audience = normalize_resource_indicator(resource)
    if not audience:
        raise ValueError('Invalid MCP resource for access token audience.')
    resource_company = resource_company_id(audience)
    if resource_company is not None and resource_company != agent.company_id:
        raise ValueError('MCP resource belongs to another company.')
    now = timezone.now()
    exp = now + mcp_access_lifetime()
    jti = uuid.uuid4().hex
    claims = {
        'token_type': 'access',
        'agent_id': str(agent.id),
        'sub': f'agent:{agent.id}',
        'company_id': agent.company_id,
        'company_name': company_name_for_agent(agent),
        'mcp_access': agent.access_mode,
        'mcp_read': agent.read_level,
        'mcp_destructive': bool(agent.allow_destructive_without_asking),
        'scope': agent_services_scope(agent),
        'jti': jti,
        'iat': int(now.timestamp()),
        'exp': int(exp.timestamp()),
        'aud': audience,
    }
    # Tests often override ``JWT_ISSUER`` without refreshing ``SIMPLE_JWT['ISSUER']``;
    # PyJWT rejects ``issuer=...`` when the token omits ``iss``, so mirror both sources.
    _issuer = api_settings.ISSUER or getattr(settings, 'JWT_ISSUER', None)
    if _issuer:
        claims['iss'] = _issuer
    setup_until = getattr(agent, 'setup_context_expires_at', None)
    setup_cid = getattr(agent, 'setup_company_id', None)
    new_company = bool(getattr(agent, 'setup_new_company_grant', False))
    setup_ttl = getattr(agent, 'setup_mcp_session_ttl_seconds', None)
    gc_bound = getattr(agent, 'global_company_id', None)
    cb_ver = getattr(agent, 'company_binding_version', None)
    setup_active = (
        new_company
        and gc_bound is not None
        and cb_ver is not None
        and setup_ttl is not None
        and setup_until is not None
        and setup_cid is not None
        and int(setup_cid) == int(agent.company_id)
        and setup_until > now
    )
    if setup_active:
        su = int(setup_until.timestamp())
        claims['setup_flow'] = True
        claims['mcp_new_company_grant'] = True
        claims['mcp_session_ttl_seconds'] = int(setup_ttl)
        claims['setup_context_company_id'] = int(setup_cid)
        claims['setup_expires_at'] = su
    claims['grant_version'] = int(getattr(agent, 'grant_version', 0) or 0)
    ga = getattr(agent, 'global_agent_id', None)
    if ga is not None:
        claims['global_agent_id'] = str(ga)
    gc = getattr(agent, 'global_company_id', None)
    if gc is not None:
        claims['global_company_id'] = str(gc)
    cb = getattr(agent, 'company_binding_version', None)
    if cb is not None:
        claims['company_binding_version'] = int(cb)
    return claims


def encode_access_token(agent: Agent, *, resource: str) -> str:
    import jwt

    ga = getattr(agent, 'global_agent_id', None)
    if ga is not None and global_agent_exchange_blocked(ga):
        raise ValueError('Global agent is revoked.')
    claims = build_agent_access_token(agent, resource=resource)
    headers = {}
    kid = getattr(settings, 'JWT_ACTIVE_KEY_ID', '')
    if kid:
        headers['kid'] = kid
    token = jwt.encode(claims, api_settings.SIGNING_KEY, algorithm=api_settings.ALGORITHM, headers=headers or None)
    return token.decode('utf-8') if isinstance(token, bytes) else token


def issue_agent_refresh(agent: Agent, *, resource: str) -> tuple[str, AgentRefreshSession]:
    bound = normalize_resource_indicator(resource)
    if not bound:
        raise ValueError('Invalid MCP resource for refresh token.')
    resource_company = resource_company_id(bound)
    if resource_company is not None and resource_company != agent.company_id:
        raise ValueError('MCP resource belongs to another company.')
    refresh = RefreshToken()
    refresh['sub'] = f'agent:{agent.id}'
    refresh['agent_id'] = str(agent.id)
    refresh['company_id'] = agent.company_id
    refresh['resource'] = bound
    refresh.set_exp(from_time=timezone.now(), lifetime=mcp_refresh_lifetime())
    jti = str(refresh['jti'])
    session = AgentRefreshSession.objects.create(
        agent=agent,
        jti=jti,
        resource=bound,
        expires_at=timezone.now() + mcp_refresh_lifetime(),
        grant_version=int(getattr(agent, 'grant_version', 0) or 0),
        services_allowed=list(agent.services_allowed or []),
        access_mode=agent.access_mode,
        read_level=agent.read_level,
        allow_destructive=bool(agent.allow_destructive_without_asking),
        global_company_id=getattr(agent, 'global_company_id', None),
        company_binding_version=getattr(agent, 'company_binding_version', None),
        setup_company_id=getattr(agent, 'setup_company_id', None),
        setup_context_expires_at=getattr(agent, 'setup_context_expires_at', None),
        setup_new_company_grant=bool(getattr(agent, 'setup_new_company_grant', False)),
    )
    return str(refresh), session


def _session_authority_ok(agent: Agent, session: AgentRefreshSession) -> bool:
    if int(getattr(agent, 'grant_version', 0) or 0) != int(getattr(session, 'grant_version', 0) or 0):
        return False
    if list(agent.services_allowed or []) != list(session.services_allowed or []):
        return False
    if agent.access_mode != session.access_mode or agent.read_level != session.read_level:
        return False
    if bool(agent.allow_destructive_without_asking) != bool(session.allow_destructive):
        return False
    agc = getattr(agent, 'global_company_id', None)
    sgc = getattr(session, 'global_company_id', None)
    if agc != sgc:
        return False
    acb = getattr(agent, 'company_binding_version', None)
    scb = getattr(session, 'company_binding_version', None)
    if acb != scb:
        return False
    asetup_c = getattr(agent, 'setup_company_id', None)
    ssetup_c = getattr(session, 'setup_company_id', None)
    asetup_e = getattr(agent, 'setup_context_expires_at', None)
    ssetup_e = getattr(session, 'setup_context_expires_at', None)
    if asetup_c != ssetup_c or asetup_e != ssetup_e:
        return False
    if bool(getattr(agent, 'setup_new_company_grant', False)) != bool(getattr(session, 'setup_new_company_grant', False)):
        return False
    r_a = access_rank(agent.access_mode)
    r_s = access_rank(session.access_mode)
    r_ra = read_rank(agent.read_level)
    r_rs = read_rank(session.read_level)
    if r_a is None or r_s is None or r_ra is None or r_rs is None:
        return False
    if r_a > r_s or r_ra > r_rs:
        return False
    if bool(agent.allow_destructive_without_asking) and not bool(session.allow_destructive):
        return False
    if not is_subset_services(list(session.services_allowed or []), list(agent.services_allowed or [])):
        return False
    return True


def revoke_all_agent_refresh_sessions(agent: Agent) -> None:
    now = timezone.now()
    AgentRefreshSession.objects.filter(agent=agent, revoked_at__isnull=True).update(revoked_at=now)


def refresh_agent_access(refresh_token: str, *, resource: str) -> tuple[str, str] | None:
    from rest_framework_simplejwt.exceptions import TokenError

    bound = normalize_resource_indicator(resource)
    if not bound:
        return None
    try:
        refresh = RefreshToken(refresh_token)
    except TokenError:
        return None
    agent_id = refresh.get('agent_id')
    jti = str(refresh.get('jti') or '')
    token_resource = normalize_resource_indicator(str(refresh.get('resource') or ''))
    if not agent_id or not jti:
        return None
    try:
        session = AgentRefreshSession.objects.select_related('agent__company').get(jti=jti, agent_id=agent_id)
    except AgentRefreshSession.DoesNotExist:
        return None
    agent = session.agent
    session_resource = normalize_resource_indicator(session.resource or '')
    if not session_resource or session_resource != bound or token_resource != bound:
        return None
    if session.revoked_at is not None:
        revoke_all_agent_refresh_sessions(agent)
        return None
    if session.expires_at <= timezone.now():
        return None
    if not agent.is_active:
        return None
    if not _session_authority_ok(agent, session):
        revoke_all_agent_refresh_sessions(agent)
        return None
    resource_company = resource_company_id(bound)
    if resource_company is not None and resource_company != agent.company_id:
        return None
    try:
        access = encode_access_token(agent, resource=bound)
    except ValueError:
        revoke_all_agent_refresh_sessions(agent)
        return None
    new_refresh, _session = issue_agent_refresh(agent, resource=bound)
    session.revoked_at = timezone.now()
    session.save(update_fields=['revoked_at'])
    return access, new_refresh
