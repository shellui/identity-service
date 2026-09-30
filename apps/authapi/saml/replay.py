"""SAML assertion replay protection (single-use assertion IDs)."""

from __future__ import annotations

import hashlib

from django.core.cache import cache

SAML_ASSERTION_CACHE_PREFIX = 'shellui:saml_assertion:'
SAML_ASSERTION_TTL_SECONDS = 24 * 60 * 60


def _cache_key(*, company_id: int, idp_entity_id: str, assertion_id: str) -> str:
    digest = hashlib.sha256(
        f'{company_id}\x1f{idp_entity_id}\x1f{assertion_id}'.encode('utf-8')
    ).hexdigest()
    return f'{SAML_ASSERTION_CACHE_PREFIX}{digest}'


def consume_assertion_id_once(*, company_id: int, idp_entity_id: str, assertion_id: str) -> bool:
    aid = str(assertion_id or '').strip()
    entity = str(idp_entity_id or '').strip()
    if not aid or not entity:
        return False
    key = _cache_key(company_id=company_id, idp_entity_id=entity, assertion_id=aid)
    return cache.add(key, 1, timeout=SAML_ASSERTION_TTL_SECONDS)
