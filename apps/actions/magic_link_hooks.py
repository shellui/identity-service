"""Magic-link login action events."""

from __future__ import annotations

from apps.actions.emit import emit_event_if_rules
from apps.actions.identity_payloads import user_event_payload
from apps.actions.models import ActionOutbox
from apps.authapi.magic_link import normalize_magic_link_language
from apps.companies.access import get_membership


def emit_magic_link_requested(
    company,
    row,
    *,
    user=None,
    language: str | None = None,
) -> list[ActionOutbox]:
    """
    Emit ``identity.auth.magic_link.requested`` as a notification.

    The payload never carries the sign-in URL, the raw token or anything else that can be
    used to sign in. Identity always sends the sign-in email itself, whether or not the
    company has a webhook rule for this event.
    Returns the queued outbox rows; empty when the company has no enabled webhook rule.
    """
    payload = {
        'request_id': str(row.pk),
        'email': row.email,
        'expires_at': row.expires_at.isoformat(),
        'source': 'magic_link',
    }
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
