"""JWT access and refresh tokens for MCP agents."""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.agents.models import Agent, AgentRefreshSession
from apps.agents.mcp_resources import normalize_mcp_resource as normalize_resource_indicator
from apps.agents.mcp_resources import resource_company_id


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
    if api_settings.ISSUER:
        claims['iss'] = api_settings.ISSUER
    setup_until = getattr(agent, 'setup_context_expires_at', None)
    setup_cid = getattr(agent, 'setup_company_id', None)
    if (
        setup_until is not None
        and setup_cid is not None
        and int(setup_cid) == int(agent.company_id)
        and setup_until > now
    ):
        su = int(setup_until.timestamp())
        claims['setup_context_company_id'] = int(setup_cid)
        claims['setup_context_exp'] = su
        claims['setup_expires_at'] = su
    claims['grant_version'] = int(getattr(agent, 'grant_version', 0) or 0)
    gc = getattr(agent, 'global_company_id', None)
    if gc is not None:
        claims['global_company_id'] = str(gc)
    cb = getattr(agent, 'company_binding_version', None)
    if cb is not None:
        claims['company_binding_version'] = int(cb)
    return claims


def encode_access_token(agent: Agent, *, resource: str) -> str:
    import jwt

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
    )
    return str(refresh), session


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
    resource_company = resource_company_id(bound)
    if resource_company is not None and resource_company != agent.company_id:
        return None
    access = encode_access_token(agent, resource=bound)
    new_refresh, _session = issue_agent_refresh(agent, resource=bound)
    session.revoked_at = timezone.now()
    session.save(update_fields=['revoked_at'])
    return access, new_refresh
