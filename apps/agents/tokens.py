"""JWT access and refresh tokens for MCP agents."""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.agents.models import Agent, AgentRefreshSession

MCP_ACCESS_AUDIENCE = 'shellui-mcp'


def mcp_access_lifetime() -> timedelta:
    return getattr(settings, 'MCP_ACCESS_TOKEN_LIFETIME', timedelta(minutes=15))


def mcp_refresh_lifetime() -> timedelta:
    return getattr(settings, 'MCP_REFRESH_TOKEN_LIFETIME', timedelta(days=30))


def agent_services_scope(agent: Agent) -> str:
    services = agent.services_allowed or []
    return ' '.join(str(s) for s in services)


def build_agent_access_token(agent: Agent) -> dict:
    now = timezone.now()
    exp = now + mcp_access_lifetime()
    jti = uuid.uuid4().hex
    claims = {
        'token_type': 'access',
        'agent_id': str(agent.id),
        'sub': f'agent:{agent.id}',
        'company_id': agent.company_id,
        'mcp_access': agent.access_mode,
        'mcp_read': agent.read_level,
        'mcp_destructive': bool(agent.allow_destructive_without_asking),
        'scope': agent_services_scope(agent),
        'jti': jti,
        'iat': int(now.timestamp()),
        'exp': int(exp.timestamp()),
    }
    if api_settings.ISSUER:
        claims['iss'] = api_settings.ISSUER
    audience = getattr(settings, 'JWT_AUDIENCE', None) or MCP_ACCESS_AUDIENCE
    claims['aud'] = audience
    if agent.project_scope:
        claims['project_scope'] = agent.project_scope
    return claims


def encode_access_token(agent: Agent) -> str:
    import jwt

    claims = build_agent_access_token(agent)
    headers = {}
    kid = getattr(settings, 'JWT_ACTIVE_KEY_ID', '')
    if kid:
        headers['kid'] = kid
    token = jwt.encode(claims, api_settings.SIGNING_KEY, algorithm=api_settings.ALGORITHM, headers=headers or None)
    return token.decode('utf-8') if isinstance(token, bytes) else token


def issue_agent_refresh(agent: Agent) -> tuple[str, AgentRefreshSession]:
    refresh = RefreshToken()
    refresh['sub'] = f'agent:{agent.id}'
    refresh['agent_id'] = str(agent.id)
    refresh['company_id'] = agent.company_id
    refresh.set_exp(from_time=timezone.now(), lifetime=mcp_refresh_lifetime())
    jti = str(refresh['jti'])
    session = AgentRefreshSession.objects.create(
        agent=agent,
        jti=jti,
        expires_at=timezone.now() + mcp_refresh_lifetime(),
    )
    return str(refresh), session


def refresh_agent_access(refresh_token: str) -> tuple[str, str] | None:
    import jwt
    from rest_framework_simplejwt.exceptions import TokenError

    try:
        refresh = RefreshToken(refresh_token)
    except TokenError:
        return None
    agent_id = refresh.get('agent_id')
    jti = str(refresh.get('jti') or '')
    if not agent_id or not jti:
        return None
    try:
        session = AgentRefreshSession.objects.select_related('agent').get(jti=jti, agent_id=agent_id)
    except AgentRefreshSession.DoesNotExist:
        return None
    if session.revoked_at is not None or session.expires_at <= timezone.now():
        return None
    agent = session.agent
    if not agent.is_active:
        return None
    access = encode_access_token(agent)
    new_refresh, _session = issue_agent_refresh(agent)
    session.revoked_at = timezone.now()
    session.save(update_fields=['revoked_at'])
    return access, new_refresh
