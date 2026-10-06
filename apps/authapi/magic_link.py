"""Passwordless magic-link tokens (company-scoped, single-use)."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db.models import Q
from django.utils import timezone

from apps.companies.models import Company

from .models import MagicLinkToken

MAGIC_LINK_VERIFY_PATH = '/api/v1/magic-link/verify'
MAGIC_LINK_LANGUAGES = frozenset({'en', 'fr'})

# Verify answers this when a token belongs to a staff account. Stable key, not translated text.
MAGIC_LINK_STAFF_DISABLED = 'magic_link_staff_disabled'
MAGIC_LINK_STAFF_DISABLED_MESSAGE = (
    'Magic link sign-in is disabled for staff accounts. Sign in with your password or SSO.'
)


def is_staff_account(user) -> bool:
    """Staff accounts never sign in with a magic link.

    A company that sends mail through its own provider (Resend, SMTP) can read every
    sign-in link in that provider's logs, so a link for a staff account would let the
    company sign in as that staff member.
    """
    if user is None:
        return False
    return bool(getattr(user, 'is_staff', False) or getattr(user, 'is_superuser', False))


def staff_account_for_email(email: str):
    """A staff or superuser account with this address, or None."""
    normalized = (email or '').strip()
    if not normalized:
        return None
    return (
        get_user_model()
        .objects.filter(email__iexact=normalized)
        .filter(Q(is_staff=True) | Q(is_superuser=True))
        .first()
    )


def magic_link_row_is_for_staff(row) -> bool:
    """True when the token's user, or any account with the token's address, is staff now."""
    if is_staff_account(getattr(row, 'user', None)):
        return True
    return staff_account_for_email(getattr(row, 'email', '')) is not None


def delete_unused_magic_link_tokens_for_user(user) -> int:
    """Delete magic-link tokens not yet used for ``user`` (by user or by address)."""
    if user is None or not getattr(user, 'pk', None):
        return 0
    match = Q(user_id=user.pk)
    email = (getattr(user, 'email', '') or '').strip()
    if email:
        match |= Q(email__iexact=email)
    deleted, _ = MagicLinkToken.objects.filter(match, consumed_at__isnull=True).delete()
    return deleted


def sign_in_page_url(redirect_to: str | None) -> str | None:
    """Origin of the app the request came from (``https://app.acme.com/``). Not a credential.

    ``redirect_to`` was already checked against the company's login redirect URLs. A
    loopback callback (a CLI sign-in) is not a page the person can open later, so it
    gives no link unless ``DEBUG`` is true. Plain ``http`` is only kept when ``DEBUG`` is true.
    """
    parts = urlsplit((redirect_to or '').strip())
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        return None
    if not settings.DEBUG:
        if parts.scheme != 'https':
            return None
        if parts.hostname in ('localhost', '127.0.0.1', '::1') or parts.hostname.endswith('.localhost'):
            return None
    host = parts.netloc.rsplit('@', 1)[-1]
    return f'{parts.scheme}://{host}/'


def normalize_magic_link_language(raw: str | None) -> str | None:
    """Map a language tag (``fr``, ``fr-FR``, ``fr_CA``) to a supported email locale."""
    lang = str(raw or '').strip().lower().replace('_', '-').split('-')[0]
    return lang if lang in MAGIC_LINK_LANGUAGES else None


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
