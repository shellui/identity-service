"""SAML assertion replay protection (single-use assertion IDs)."""

from __future__ import annotations

import hashlib
import logging

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)

SAML_ASSERTION_CACHE_PREFIX = 'shellui:saml_assertion:'
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
