"""Single-use SAML AuthnRequest / InResponseTo tracking (server-side)."""

from __future__ import annotations

import hashlib

from django.core.cache import cache

SAML_REQUEST_ID_PREFIX = 'shellui:saml_request_id:'
SAML_REQUEST_ID_TTL_SECONDS = 15 * 60


def stash_saml_request_id(*, request_id: str, payload: dict) -> None:
    rid = str(request_id or '').strip()
    if not rid or not isinstance(payload, dict):
        return
    digest = hashlib.sha256(rid.encode('utf-8')).hexdigest()
    cache.set(
        f'{SAML_REQUEST_ID_PREFIX}{digest}',
        payload,
        timeout=SAML_REQUEST_ID_TTL_SECONDS,
    )


def consume_saml_request_id(request_id: str) -> dict | None:
    rid = str(request_id or '').strip()
    if not rid:
        return None
    digest = hashlib.sha256(rid.encode('utf-8')).hexdigest()
    key = f'{SAML_REQUEST_ID_PREFIX}{digest}'
    consumed_key = f'{key}:used'
    if not cache.add(consumed_key, 1, timeout=SAML_REQUEST_ID_TTL_SECONDS):
        return None
    value = cache.get(key)
    cache.delete(key)
    return value if isinstance(value, dict) else None
