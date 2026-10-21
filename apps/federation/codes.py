"""One-time authorization codes and opaque userinfo tokens. Cache only, never logged."""

from __future__ import annotations

import hashlib
import secrets

from django.conf import settings
from django.core.cache import cache


def store_code(payload: dict) -> str:
    code = secrets.token_urlsafe(32)
    cache.set(_code_key(code), payload, timeout=_code_ttl())
    return code


def consume_code(code: str) -> dict | None:
    """Return the payload once. A second presentation is a miss."""
    if not code:
        return None
    key = _code_key(code)
    if not cache.add(f'{key}:used', 1, timeout=_code_ttl()):
        cache.delete(key)
        return None
    payload = cache.get(key)
    cache.delete(key)
    if not isinstance(payload, dict):
        return None
    return payload


def store_access_token(payload: dict) -> str:
    token = secrets.token_urlsafe(32)
    cache.set(_access_key(token), payload, timeout=_code_ttl())
    return token


def read_access_token(token: str) -> dict | None:
    payload = cache.get(_access_key(token))
    if not isinstance(payload, dict):
        return None
    return payload


def _code_ttl() -> int:
    return int(getattr(settings, 'OIDC_CODE_TTL_SECONDS', 60))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _code_key(code: str) -> str:
    return f'federation:code:{_digest(code)}'


def _access_key(token: str) -> str:
    return f'federation:access:{_digest(token)}'
