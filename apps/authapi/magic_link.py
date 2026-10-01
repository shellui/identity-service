"""Passwordless magic-link tokens (company-scoped, single-use)."""

from __future__ import annotations

import hashlib
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


def hash_magic_link_token(raw: str) -> str:
    return hashlib.sha256((raw or '').encode('utf-8')).hexdigest()


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
    # Request-derived URLs come from the Host header; only trust them for local development.
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
    fallback_base_url: str | None = None,
) -> str:
    base = (base_url or identity_public_base_url(fallback=fallback_base_url)).rstrip('/')
    if not settings.DEBUG and not base.startswith('https://'):
        raise ImproperlyConfigured('Magic link URLs must use HTTPS when DEBUG=false.')
    query = urlencode({'token': token, 'company_id': str(company_id)})
    return f'{base}{MAGIC_LINK_VERIFY_PATH}?{query}'


def magic_link_url_for_request(
    request_id: str | uuid.UUID | None,
    *,
    raw_token: str | None = None,
    fallback_base_url: str | None = None,
) -> str | None:
    if not request_id or not raw_token:
        return None
    try:
        row = MagicLinkToken.objects.get(pk=request_id)
    except MagicLinkToken.DoesNotExist:
        return None
    if row.consumed_at is not None or row.expires_at <= timezone.now():
        return None
    return build_magic_link_verify_url(
        token=raw_token,
        company_id=row.company_id,
        fallback_base_url=fallback_base_url,
    )


def create_magic_link_token(
    *,
    company: Company,
    email: str,
    redirect_to: str,
    user=None,
    client_timezone: str = '',
    client_device_id: str | None = None,
) -> tuple[MagicLinkToken, str]:
    normalized = (email or '').strip().lower()
    raw_token = secrets.token_urlsafe(32)
    expires_at = timezone.now() + magic_link_ttl()
    row = MagicLinkToken.objects.create(
        company=company,
        email=normalized,
        user=user,
        token_hash=hash_magic_link_token(raw_token),
        redirect_to=redirect_to,
        expires_at=expires_at,
        client_timezone=(client_timezone or '')[:64],
        client_device_id=(client_device_id or '')[:128] or None,
    )
    return row, raw_token


def lookup_magic_link_token(
    *,
    raw_token: str,
    company_id: int,
) -> tuple[MagicLinkToken | None, str | None]:
    """Validate a token without consuming it (for browser confirmation GET)."""
    token = (raw_token or '').strip()
    if not token:
        return None, 'Missing token.'
    token_hash = hash_magic_link_token(token)
    now = timezone.now()
    row = (
        MagicLinkToken.objects.filter(token_hash=token_hash, company_id=company_id)
        .select_related('company', 'user')
        .first()
    )
    if row is None:
        return None, 'Invalid or expired magic link.'
    if row.consumed_at is not None:
        return None, 'Magic link already used.'
    if row.expires_at <= now:
        return None, 'Magic link expired.'
    return row, None


def redeem_magic_link_token(
    *,
    raw_token: str,
    company_id: int,
) -> tuple[MagicLinkToken | None, str | None]:
    token = (raw_token or '').strip()
    if not token:
        return None, 'Missing token.'
    token_hash = hash_magic_link_token(token)
    now = timezone.now()
    updated = MagicLinkToken.objects.filter(
        token_hash=token_hash,
        company_id=company_id,
        consumed_at__isnull=True,
        expires_at__gt=now,
    ).update(consumed_at=now)
    if updated == 0:
        row = (
            MagicLinkToken.objects.filter(token_hash=token_hash, company_id=company_id)
            .only('consumed_at', 'expires_at')
            .first()
        )
        if row is None:
            return None, 'Invalid or expired magic link.'
        if row.consumed_at is not None:
            return None, 'Magic link already used.'
        return None, 'Magic link expired.'

    row = MagicLinkToken.objects.select_related('company', 'user').get(
        token_hash=token_hash,
        company_id=company_id,
    )
    return row, None
