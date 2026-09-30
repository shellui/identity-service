"""SAML assertion replay protection (single-use assertion IDs)."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from onelogin.saml2.auth import OneLogin_Saml2_Auth

logger = logging.getLogger(__name__)

SAML_ASSERTION_CACHE_PREFIX = 'shellui:saml_assertion:'
SAML_ASSERTION_MAX_TTL_SECONDS = 24 * 60 * 60
SAML_ASSERTION_MAX_VALIDITY_SECONDS = 15 * 60
_locmem_warning_emitted = False


def ensure_saml_replay_cache_backend() -> None:
    global _locmem_warning_emitted
    backend = str(settings.CACHES.get('default', {}).get('BACKEND', '')).lower()
    if 'locmem' not in backend:
        return
    message = (
        'SAML assertion replay protection requires a shared cache backend (not LocMemCache). '
        'Multi-worker deployments will not detect replays until this is fixed.'
    )
    if settings.DEBUG:
        if not _locmem_warning_emitted:
            logger.warning(message)
            _locmem_warning_emitted = True
        return
    raise ImproperlyConfigured(message)


def _cache_key(*, company_id: int, idp_entity_id: str, assertion_id: str) -> str:
    digest = hashlib.sha256(
        f'{company_id}\x1f{idp_entity_id}\x1f{assertion_id}'.encode('utf-8')
    ).hexdigest()
    return f'{SAML_ASSERTION_CACHE_PREFIX}{digest}'


def _parse_saml_instant(value: str | None) -> datetime | None:
    raw = str(value or '').strip()
    if not raw:
        return None
    if raw.endswith('Z'):
        raw = raw[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def assertion_replay_ttl_seconds(auth: OneLogin_Saml2_Auth) -> int | None:
    """Return cache TTL for this assertion, or None when the assertion lifetime is invalid."""
    raw = auth.get_last_assertion_not_on_or_after()
    not_after = None
    if isinstance(raw, (int, float)):
        not_after = datetime.fromtimestamp(float(raw), tz=timezone.utc)
    else:
        not_after = _parse_saml_instant(str(raw) if raw is not None else None)
    if not_after is None:
        return None
    now = datetime.now(timezone.utc)
    remaining = int((not_after - now).total_seconds())
    if remaining <= 0:
        return None
    if remaining > SAML_ASSERTION_MAX_VALIDITY_SECONDS:
        return None
    return min(remaining + 90, SAML_ASSERTION_MAX_TTL_SECONDS)


def consume_assertion_id_once(
    *,
    company_id: int,
    idp_entity_id: str,
    assertion_id: str,
    ttl_seconds: int,
) -> bool:
    aid = str(assertion_id or '').strip()
    entity = str(idp_entity_id or '').strip()
    if not aid or not entity or ttl_seconds <= 0:
        return False
    key = _cache_key(company_id=company_id, idp_entity_id=entity, assertion_id=aid)
    return cache.add(key, 1, timeout=ttl_seconds)
