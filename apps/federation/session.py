"""Host-only browser session for prompt=none. Not the Django session cookie."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.cache import cache

from apps.federation.role import is_global
from apps.federation.signing import unix_now

User = get_user_model()

COOKIE = 'shellui_op_session'
SALT = 'federation.op.session.v1'
_SID_CACHE = 'federation:op-sids:'


def remember_provider_session(request, user) -> None:
    """Ask middleware to set the provider cookie after a completed sign-in."""
    if not is_global() or user is None or not getattr(user, 'is_active', False):
        return
    getattr(request, '_request', request).federation_op_user_id = user.pk


def forget_provider_session(request) -> None:
    """Ask middleware to clear the provider cookie. Works for DRF and Django requests."""
    getattr(request, '_request', request).federation_clear_op_session = True


def remember_verified_email(user, email: str) -> None:
    """Record a proved address. No-op unless this process is the provider."""
    if not is_global() or user is None:
        return
    from apps.authapi.oauth_user import normalize_oauth_email

    from apps.federation.models import VerifiedEmail

    normalized = normalize_oauth_email(email or '')
    if not normalized or '@' not in normalized:
        return
    if normalize_oauth_email(getattr(user, 'email', '') or '') != normalized:
        return
    VerifiedEmail.objects.update_or_create(user=user, defaults={'email': normalized})


def email_is_verified(user) -> bool:
    from apps.authapi.oauth_user import normalize_oauth_email

    from apps.federation.models import VerifiedEmail

    row = VerifiedEmail.objects.filter(user=user).first()
    if row is None:
        return False
    return row.email == normalize_oauth_email(getattr(user, 'email', '') or '')


def read_session(request):
    """Return ``(user, sid)`` or ``None`` when the cookie is missing or bad."""
    raw = request.COOKIES.get(COOKIE)
    if not raw:
        return None
    max_age = int(getattr(settings, 'OIDC_SESSION_TTL_SECONDS', 12 * 60 * 60))
    try:
        data = signing.loads(raw, salt=SALT, max_age=max_age)
    except signing.BadSignature:
        return None
    if not isinstance(data, dict):
        return None
    try:
        user_id = int(data.get('uid'))
    except (TypeError, ValueError):
        return None
    sid = str(data.get('sid') or '')
    if not sid:
        return None
    user = User.objects.filter(pk=user_id, is_active=True).first()
    if user is None:
        return None
    return user, sid


def set_cookie(response, user) -> str:
    sid = uuid.uuid4().hex
    payload = signing.dumps(
        {'uid': user.pk, 'sid': sid, 'iat': unix_now()},
        salt=SALT,
    )
    _store_sid(user.pk, sid)
    secure = bool(getattr(settings, 'SESSION_COOKIE_SECURE', False))
    response.set_cookie(
        COOKIE,
        payload,
        max_age=int(getattr(settings, 'OIDC_SESSION_TTL_SECONDS', 12 * 60 * 60)),
        httponly=True,
        secure=secure,
        samesite='None' if secure else 'Lax',
        path='/oauth/',
    )
    return sid


def clear_cookie(response) -> None:
    response.delete_cookie(COOKIE, path='/oauth/')


def session_ids(user_id: int) -> list[str]:
    stored = cache.get(f'{_SID_CACHE}{user_id}')
    if not isinstance(stored, list):
        return []
    return [str(item) for item in stored if item]


def clear_session_ids(user_id: int) -> None:
    cache.delete(f'{_SID_CACHE}{user_id}')


def _store_sid(user_id: int, sid: str) -> None:
    key = f'{_SID_CACHE}{user_id}'
    current = session_ids(user_id)
    current.append(sid)
    ttl = int(getattr(settings, 'OIDC_SESSION_TTL_SECONDS', 12 * 60 * 60))
    cache.set(key, current[-20:], timeout=ttl)
