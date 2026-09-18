"""Server-side refresh token rotation, revocation, and access-token denylist."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone as dt_timezone

from django.core.cache import cache
from django.utils import timezone

from .models import RefreshTokenSession
from .tokens import ShellUIRefreshToken

_ACCESS_DENY_CACHE_PREFIX = 'shellui:access_deny:'


def _expires_at_from_refresh(refresh: ShellUIRefreshToken) -> datetime:
    exp = refresh.get('exp')
    if exp is None:
        raise ValueError('Refresh token missing exp claim.')
    return datetime.fromtimestamp(int(exp), tz=dt_timezone.utc)


def register_refresh_session(
    *,
    user,
    company,
    refresh: ShellUIRefreshToken,
    family_id: uuid.UUID | None = None,
) -> RefreshTokenSession:
    """Persist a refresh JWT and bind ``sid`` on the in-memory token object."""
    session_id = uuid.uuid4()
    jti = str(refresh['jti'])
    session = RefreshTokenSession.objects.create(
        id=session_id,
        user=user,
        company=company,
        jti=jti,
        family_id=family_id or uuid.uuid4(),
        expires_at=_expires_at_from_refresh(refresh),
    )
    refresh['sid'] = str(session_id)
    return session


def bind_access_session(*, access, session_id: uuid.UUID) -> None:
    access['sid'] = str(session_id)


def validate_refresh_session(refresh: ShellUIRefreshToken) -> tuple[RefreshTokenSession | None, str | None]:
    jti = str(refresh.get('jti') or '').strip()
    if not jti:
        return None, 'Invalid refresh token.'

    try:
        session = RefreshTokenSession.objects.get(jti=jti)
    except RefreshTokenSession.DoesNotExist:
        return None, 'Refresh token revoked or unknown.'

    if session.revoked_at is not None:
        revoke_refresh_family(session.family_id)
        return None, 'Refresh token has been revoked.'

    if session.expires_at <= timezone.now():
        return None, 'Refresh token expired.'

    token_user_id = refresh.get('user_id')
    if token_user_id is None or int(session.user_id) != int(token_user_id):
        return None, 'Refresh token user mismatch.'

    token_company_id = refresh.get('company_id')
    if token_company_id is not None and int(session.company_id) != int(token_company_id):
        return None, 'Refresh token company mismatch.'

    return session, None


def get_refresh_session_for_jti(jti: str) -> RefreshTokenSession | None:
    normalized = (jti or '').strip()
    if not normalized:
        return None
    return RefreshTokenSession.objects.filter(jti=normalized).first()


def revoke_refresh_session(session: RefreshTokenSession) -> None:
    if session.revoked_at is None:
        session.revoked_at = timezone.now()
        session.save(update_fields=['revoked_at'])


def revoke_refresh_by_jti(jti: str) -> None:
    RefreshTokenSession.objects.filter(
        jti=(jti or '').strip(),
        revoked_at__isnull=True,
    ).update(revoked_at=timezone.now())


def revoke_refresh_family(family_id: uuid.UUID) -> None:
    RefreshTokenSession.objects.filter(
        family_id=family_id,
        revoked_at__isnull=True,
    ).update(revoked_at=timezone.now())


def revoke_session_by_sid(session_id: str | uuid.UUID) -> bool:
    try:
        parsed = uuid.UUID(str(session_id))
    except (TypeError, ValueError):
        return False
    updated = RefreshTokenSession.objects.filter(
        pk=parsed,
        revoked_at__isnull=True,
    ).update(revoked_at=timezone.now())
    return updated > 0


def denylist_access_jti(jti: str, *, exp_unix: int) -> None:
    ttl = max(1, int(exp_unix) - int(timezone.now().timestamp()))
    cache.set(f'{_ACCESS_DENY_CACHE_PREFIX}{jti}', '1', timeout=ttl)


def is_access_jti_denied(jti: str | None) -> bool:
    if not jti:
        return False
    return cache.get(f'{_ACCESS_DENY_CACHE_PREFIX}{jti}') is not None
