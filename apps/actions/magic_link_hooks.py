"""Magic-link login action events."""

from __future__ import annotations

from django.utils import timezone

from apps.actions.emit import emit_event_if_rules
from apps.actions.identity_payloads import user_event_payload


def emit_magic_link_requested(company, row, *, user=None) -> None:
    """
    Emit ``identity.auth.magic_link.requested`` without secrets in the webhook payload.

    Email templates receive ``magic_link_url`` at delivery time (see email handler).
    """
    payload = {
        'request_id': str(row.pk),
        'email': row.email,
        'expires_at': row.expires_at.isoformat(),
        'source': 'magic_link',
    }
    if user is not None and getattr(user, 'pk', None):
        prefs = user_event_payload(user, source='magic_link')
        payload['user_id'] = prefs['user_id']
        payload['language'] = prefs['language']
        payload['region'] = prefs['region']
    else:
        payload['language'] = 'en'
        payload['region'] = 'UTC'
    emit_event_if_rules('identity.auth.magic_link.requested', company, payload)
