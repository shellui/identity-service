"""Mint and validate personal MCP agent bearer tokens."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.agents.models import Agent, PersonalAgentCredential
from apps.agents.mcp_resources import company_mcp_resource_url
from apps.agents.tokens import agent_services_scope, apply_owner_user_id_claim, company_name_for_agent


def personal_agent_max_lifetime() -> timedelta:
    days = int(getattr(settings, 'MCP_PERSONAL_AGENT_MAX_LIFETIME_DAYS', 90) or 90)
    return timedelta(days=max(1, min(days, 366)))


def digest_agent_token_jti(jti: str) -> str:
    return hashlib.sha256(jti.encode('utf-8')).hexdigest()


def parse_required_expires_at(raw) -> datetime | None:
    if raw is None or raw == '':
        return None
    if isinstance(raw, datetime):
        dt = raw
    else:
        dt = parse_datetime(str(raw).strip())
    if dt is None:
        return None
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    return dt


def normalize_personal_agent_services(services: list[str]) -> list[str] | None:
    allowed = {choice[0] for choice in Agent.SERVICE_CHOICES}
    cleaned = [s for s in services if s in allowed and s != Agent.SERVICE_AI]
    if not cleaned:
        return None
    if Agent.SERVICE_AI not in cleaned:
        cleaned.append(Agent.SERVICE_AI)
    return cleaned


def encode_personal_agent_access_token(
    agent: Agent,
    *,
    resource: str,
    expires_at: datetime,
    personal_token_id: uuid.UUID,
    jti: str,
) -> str:
    import jwt
    from rest_framework_simplejwt.settings import api_settings

    from apps.agents.mcp_resources import normalize_mcp_resource, resource_company_id

    audience = normalize_mcp_resource(resource)
    if not audience:
        raise ValueError('Invalid MCP resource for access token audience.')
    resource_company = resource_company_id(audience)
    if resource_company is not None and resource_company != agent.company_id:
        raise ValueError('MCP resource belongs to another company.')
    now = timezone.now()
    if expires_at <= now:
        raise ValueError('Expiry must be in the future.')
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
        'personal_token_id': str(personal_token_id),
        'jti': jti,
        'iat': int(now.timestamp()),
        'exp': int(expires_at.timestamp()),
        'aud': audience,
        'grant_version': int(getattr(agent, 'grant_version', 0) or 0),
    }
    gc = getattr(agent, 'global_company_id', None)
    if gc is not None:
        claims['global_company_id'] = str(gc)
    cb = getattr(agent, 'company_binding_version', None)
    if cb is not None:
        claims['company_binding_version'] = int(cb)
    apply_owner_user_id_claim(claims, agent)
    _issuer = api_settings.ISSUER or getattr(settings, 'JWT_ISSUER', None)
    if _issuer:
        claims['iss'] = _issuer
    headers = {}
    kid = getattr(settings, 'JWT_ACTIVE_KEY_ID', '')
    if kid:
        headers['kid'] = kid
    token = jwt.encode(claims, api_settings.SIGNING_KEY, algorithm=api_settings.ALGORITHM, headers=headers or None)
    return token.decode('utf-8') if isinstance(token, bytes) else token


@transaction.atomic
def create_personal_agent_credential(
    *,
    user,
    company,
    name: str,
    services: list[str],
    access_mode: str,
    read_level: str,
    allow_destructive: bool,
    expires_at: datetime,
) -> tuple[PersonalAgentCredential, str]:
    resource = company_mcp_resource_url(company.id)
    if not resource:
        raise ValueError('MCP is not configured for this company.')
    jti = uuid.uuid4().hex
    credential_id = uuid.uuid4()
    agent = Agent.objects.create(
        company=company,
        name=name[:255],
        oauth_client=None,
        created_by=user,
        access_mode=access_mode,
        allow_destructive_without_asking=allow_destructive,
        read_level=read_level,
        services_allowed=services,
        expires_at=expires_at,
    )
    row = PersonalAgentCredential.objects.create(
        id=credential_id,
        agent=agent,
        company=company,
        user=user,
        name=name[:255],
        token_jti_digest=digest_agent_token_jti(jti),
        expires_at=expires_at,
    )
    access = encode_personal_agent_access_token(
        agent,
        resource=resource,
        expires_at=expires_at,
        personal_token_id=credential_id,
        jti=jti,
    )
    return row, access
