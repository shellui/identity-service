"""Passwordless magic-link tokens (company-scoped, single-use)."""

from __future__ import annotations

import secrets
import uuid
from datetime import timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from apps.companies.models import Company

from .models import MagicLinkToken

MAGIC_LINK_VERIFY_PATH = '/api/v1/magic-link/verify'


def magic_link_globally_enabled() -> bool:
    return bool(getattr(settings, 'MAGIC_LINK_ENABLED', True))


def magic_link_enabled_for_company(company: Company) -> bool:
    if not magic_link_globally_enabled():
        return False
    return bool(getattr(company, 'enable_magic_link', True))


def magic_link_ttl() -> timedelta:
    raw = int(getattr(settings, 'MAGIC_LINK_TTL_SECONDS', 1800) or 1800)
    return timedelta(seconds=max(60, raw))


def identity_public_base_url(*, fallback: str | None = None) -> str:
    issuer = (getattr(settings, 'JWT_ISSUER', None) or '').strip().rstrip('/')
    if issuer:
        return issuer
    if fallback:
        base = fallback.rstrip('/')
        if base.startswith('https://') or (settings.DEBUG and base.startswith('http://')):
            return base
    if settings.DEBUG and fallback:
        return fallback.rstrip('/')
    raise ImproperlyConfigured(
        'JWT_ISSUER must be set to the public HTTPS base URL of identity-service to build magic links.'
    )


def build_magic_link_verify_url(
    *,
    token: str,
    company_id: int,
    base_url: str | None = None,
) -> str:
    base = (base_url or identity_public_base_url()).rstrip('/')
    if not settings.DEBUG and not base.startswith('https://'):
        raise ImproperlyConfigured('Magic link URLs must use HTTPS when DEBUG=false.')
    query = urlencode({'token': token, 'company_id': str(company_id)})
    return f'{base}{MAGIC_LINK_VERIFY_PATH}?{query}'


def magic_link_url_for_request(request_id: str | uuid.UUID | None) -> str | None:
    if not request_id:
        return None
    try:
        row = MagicLinkToken.objects.get(pk=request_id)
    except MagicLinkToken.DoesNotExist:
        return None
    if row.consumed_at is not None or row.expires_at <= timezone.now():
        return None
    return build_magic_link_verify_url(token=row.token, company_id=row.company_id)


def create_magic_link_token(
    *,
    company: Company,
    email: str,
    redirect_to: str,
    user=None,
    client_timezone: str = '',
    client_device_id: str | None = None,
) -> MagicLinkToken:
    normalized = (email or '').strip().lower()
    token = secrets.token_urlsafe(32)
    expires_at = timezone.now() + magic_link_ttl()
    return MagicLinkToken.objects.create(
        company=company,
        email=normalized,
        user=user,
        token=token,
        redirect_to=redirect_to,
        expires_at=expires_at,
        client_timezone=(client_timezone or '')[:64],
        client_device_id=(client_device_id or '')[:128] or None,
    )


def redeem_magic_link_token(
    *,
    raw_token: str,
    company_id: int,
) -> tuple[MagicLinkToken | None, str | None]:
    token = (raw_token or '').strip()
    if not token:
        return None, 'Missing token.'
    try:
        row = (
            MagicLinkToken.objects.select_related('company', 'user')
            .get(token=token, company_id=company_id)
        )
    except MagicLinkToken.DoesNotExist:
        return None, 'Invalid or expired magic link.'

    if row.consumed_at is not None:
        return None, 'Magic link already used.'

    if row.expires_at <= timezone.now():
        return None, 'Magic link expired.'

    row.consumed_at = timezone.now()
    row.save(update_fields=['consumed_at'])
    return row, None
