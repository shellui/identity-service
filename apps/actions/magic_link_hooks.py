"""Magic-link login action events."""

from __future__ import annotations

import logging

from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from apps.actions.emit import emit_event_if_rules
from apps.actions.identity_payloads import user_event_payload
from apps.actions.models import ActionOutbox
from apps.authapi.magic_link import magic_link_url_for_request, normalize_magic_link_language
from apps.companies.access import get_membership

logger = logging.getLogger(__name__)


def emit_magic_link_requested(
    company,
    row,
    *,
    user=None,
    raw_token: str | None = None,
    fallback_base_url: str | None = None,
    language: str | None = None,
) -> list[ActionOutbox]:
    """
    Emit ``identity.auth.magic_link.requested`` with the one-time sign-in URL.

    ``magic_link_url`` is a live login credential until ``expires_at`` or first use.
    Returns the queued outbox rows; empty when the company has no enabled webhook rule.
    """
    payload = {
        'request_id': str(row.pk),
        'email': row.email,
        'expires_at': row.expires_at.isoformat(),
        'source': 'magic_link',
    }
    try:
        magic_link_url = magic_link_url_for_request(
            row.pk,
            raw_token=raw_token,
            fallback_base_url=fallback_base_url,
        )
    except ImproperlyConfigured:
        logger.exception('magic_link_webhook_url_failed company_id=%s request_id=%s', company.pk, row.pk)
        magic_link_url = None
    if magic_link_url:
        payload['magic_link_url'] = magic_link_url
    if user is not None and getattr(user, 'pk', None) and get_membership(company, user) is not None:
        prefs = user_event_payload(user, source='magic_link')
        payload['user_id'] = prefs['user_id']
        payload['language'] = prefs['language']
        payload['region'] = prefs['region']
    else:
        payload['language'] = 'en'
        payload['region'] = 'UTC'
    requested_lang = normalize_magic_link_language(language)
    if requested_lang:
        payload['language'] = requested_lang
    return emit_event_if_rules('identity.auth.magic_link.requested', company, payload)
