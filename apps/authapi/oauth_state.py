"""Signed OAuth state for identity-owned provider callbacks."""

from __future__ import annotations

import hashlib
import secrets

from django.conf import settings
from django.core import signing
from django.core.cache import cache

OAUTH_STATE_SALT = 'shellui.oauth.authorize.v1'
OAUTH_STATE_MAX_AGE_SECONDS = 15 * 60
OAUTH_STATE_NONCE_COOKIE = 'shellui_oauth_state_nonce'
OAUTH_STATE_USED_CACHE_PREFIX = 'shellui:oauth_state_used:'
OAUTH_PKCE_CACHE_PREFIX = 'shellui:oauth_pkce:'
OAUTH_APPLE_POST_CACHE_PREFIX = 'shellui:oauth_apple_post:'
OAUTH_APPLE_POST_STATE_USED_PREFIX = 'shellui:oauth_apple_post_state:'
OAUTH_APPLE_BRIDGE_COOKIE = 'shellui_apple_oauth_bridge'
OAUTH_APPLE_BRIDGE_CACHE_PREFIX = 'shellui:oauth_apple_bridge:'
OAUTH_PKCE_CONSUMED_PREFIX = 'shellui:oauth_pkce_used:'


def stash_oauth_pkce_verifier(nonce: str, verifier: str) -> None:
    key = str(nonce or '').strip()
    value = str(verifier or '').strip()
    if not key or not value:
        return
    cache.set(f'{OAUTH_PKCE_CACHE_PREFIX}{key}', value, timeout=OAUTH_STATE_MAX_AGE_SECONDS)


def stash_apple_oauth_post_payload(nonce: str, payload: dict) -> None:
    key = str(nonce or '').strip()
    if not key or not isinstance(payload, dict):
        return
    cache.set(
        f'{OAUTH_APPLE_POST_CACHE_PREFIX}{key}',
        payload,
        timeout=OAUTH_STATE_MAX_AGE_SECONDS,
    )


def consume_apple_oauth_post_payload(nonce: str) -> dict | None:
    key = str(nonce or '').strip()
    if not key:
        return None
    cache_key = f'{OAUTH_APPLE_POST_CACHE_PREFIX}{key}'
    value = cache.get(cache_key)
    if isinstance(value, dict):
        cache.delete(cache_key)
        return value
    return None


def consume_oauth_pkce_verifier(nonce: str) -> str | None:
    key = str(nonce or '').strip()
    if not key:
        return None
    consumed_key = f'{OAUTH_PKCE_CONSUMED_PREFIX}{key}'
    if not cache.add(consumed_key, 1, timeout=OAUTH_STATE_MAX_AGE_SECONDS):
        return None
    cache_key = f'{OAUTH_PKCE_CACHE_PREFIX}{key}'
    value = cache.get(cache_key)
    cache.delete(cache_key)
    if value:
        return str(value)
    cache.delete(consumed_key)
    return None


def consume_apple_form_post_state_once(state: str) -> bool:
    digest = hashlib.sha256((state or '').encode('utf-8')).hexdigest()
    key = f'{OAUTH_APPLE_POST_STATE_USED_PREFIX}{digest}'
    return cache.add(key, 1, timeout=OAUTH_STATE_MAX_AGE_SECONDS)


def stash_apple_oauth_bridge_payload(bridge_token: str, payload: dict) -> None:
    token = str(bridge_token or '').strip()
    if not token or not isinstance(payload, dict):
        return
    cache.set(
        f'{OAUTH_APPLE_BRIDGE_CACHE_PREFIX}{token}',
        payload,
        timeout=OAUTH_STATE_MAX_AGE_SECONDS,
    )


def consume_apple_oauth_bridge_payload(bridge_token: str) -> dict | None:
    token = str(bridge_token or '').strip()
    if not token:
        return None
    cache_key = f'{OAUTH_APPLE_BRIDGE_CACHE_PREFIX}{token}'
    if not cache.add(f'{cache_key}:used', 1, timeout=OAUTH_STATE_MAX_AGE_SECONDS):
        return None
    value = cache.get(cache_key)
    cache.delete(cache_key)
    return value if isinstance(value, dict) else None


def apple_oauth_bridge_cookie_value(bridge_token: str) -> dict:
    secure = bool(getattr(settings, 'SESSION_COOKIE_SECURE', not settings.DEBUG))
    return {
        'key': OAUTH_APPLE_BRIDGE_COOKIE,
        'value': bridge_token,
        'max_age': OAUTH_STATE_MAX_AGE_SECONDS,
        'httponly': True,
        'samesite': 'Lax',
        'secure': secure,
    }


def build_oauth_state(
    *,
    provider: str,
    redirect_to: str,
    company_id: int,
    company_oauth_client_id: int | None = None,
    client_timezone: str | None = None,
    client_device_id: str | None = None,
    token_delivery: str | None = None,
    nonce: str | None = None,
) -> tuple[str, str]:
    """
    Returns (signed_state, nonce). The nonce must be stored in the browser cookie
    ``OAUTH_STATE_NONCE_COOKIE`` before redirecting to the provider.
    """
    state_nonce = (nonce or '').strip() or secrets.token_urlsafe(32)
    payload: dict = {
        'provider': str(provider).strip().lower(),
        'redirect_to': str(redirect_to).strip(),
        'company_id': int(company_id),
        'nonce': state_nonce,
    }
    if company_oauth_client_id is not None:
        payload['company_oauth_client_id'] = int(company_oauth_client_id)
    tz = (client_timezone or '').strip()
    if tz:
        payload['client_timezone'] = tz[:64]
    dev = (client_device_id or '').strip()
    if dev:
        payload['client_device_id'] = dev[:128]
    delivery = (token_delivery or '').strip().lower()
    if delivery in {'code', 'fragment'}:
        payload['token_delivery'] = delivery
    return signing.dumps(payload, salt=OAUTH_STATE_SALT), state_nonce


def parse_oauth_state(state: str | None) -> tuple[dict | None, str | None]:
    """
    Returns (payload, None) or (None, error_message).
    """
    raw = (state or '').strip()
    if not raw:
        return None, 'Missing OAuth state.'
    try:
        payload = signing.loads(raw, salt=OAUTH_STATE_SALT, max_age=OAUTH_STATE_MAX_AGE_SECONDS)
    except signing.SignatureExpired:
        return None, 'OAuth state expired.'
    except signing.BadSignature:
        return None, 'Invalid OAuth state.'
    if not isinstance(payload, dict):
        return None, 'Invalid OAuth state.'
    provider = str(payload.get('provider') or '').strip().lower()
    redirect_to = str(payload.get('redirect_to') or '').strip()
    try:
        company_id = int(payload.get('company_id'))
    except (TypeError, ValueError):
        return None, 'Invalid OAuth state company_id.'
    nonce = str(payload.get('nonce') or '').strip()
    if not provider or not redirect_to or company_id <= 0 or not nonce:
        return None, 'Invalid OAuth state payload.'
    out: dict = {
        'provider': provider,
        'redirect_to': redirect_to,
        'company_id': company_id,
        'nonce': nonce,
    }
    raw_client = payload.get('company_oauth_client_id')
    if raw_client is not None and str(raw_client).strip() != '':
        try:
            cid = int(raw_client)
        except (TypeError, ValueError):
            return None, 'Invalid OAuth state company_oauth_client_id.'
        if cid > 0:
            out['company_oauth_client_id'] = cid
    tz = str(payload.get('client_timezone') or '').strip()
    if tz:
        out['client_timezone'] = tz[:64]
    dev = str(payload.get('client_device_id') or '').strip()
    if dev:
        out['client_device_id'] = dev[:128]
    delivery = str(payload.get('token_delivery') or '').strip().lower()
    if delivery in {'code', 'fragment'}:
        out['token_delivery'] = delivery
    return out, None


def _state_replay_cache_key(state: str) -> str:
    digest = hashlib.sha256(state.encode('utf-8')).hexdigest()
    return f'{OAUTH_STATE_USED_CACHE_PREFIX}{digest}'


def consume_oauth_state_once(state: str) -> bool:
    """Mark signed state as used (single-use). Returns False if already consumed."""
    key = _state_replay_cache_key(state)
    return cache.add(key, 1, timeout=OAUTH_STATE_MAX_AGE_SECONDS)


def verify_oauth_state_request(state: str | None, request) -> tuple[dict | None, str | None]:
    """
    Validate signed state, bind to the HttpOnly cookie nonce, and consume state once.
    """
    raw = (state or '').strip()
    payload, err = parse_oauth_state(raw)
    if err or not payload:
        return None, err or 'Invalid OAuth state.'
    cookie_nonce = (request.COOKIES.get(OAUTH_STATE_NONCE_COOKIE) or '').strip()
    if not cookie_nonce or cookie_nonce != payload.get('nonce'):
        return None, 'OAuth state does not match this browser session.'
    if not consume_oauth_state_once(raw):
        return None, 'OAuth state already used.'
    return payload, None


def oauth_state_nonce_cookie_value(nonce: str) -> dict:
    secure = bool(getattr(settings, 'SESSION_COOKIE_SECURE', not settings.DEBUG))
    return {
        'key': OAUTH_STATE_NONCE_COOKIE,
        'value': nonce,
        'max_age': OAUTH_STATE_MAX_AGE_SECONDS,
        'httponly': True,
        'samesite': 'Lax',
        'secure': secure,
    }
