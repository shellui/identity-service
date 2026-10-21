"""Provider-role webhook events. Other roles do not emit them."""

from __future__ import annotations

from apps.actions.emit import emit_event_if_rules
from apps.companies.models import Company
from apps.federation.role import is_global


def emit_authorize_succeeded(*, user, client_id: str) -> None:
    if not is_global():
        return
    payload = _user_payload(user, client_id)
    for company in _companies(user):
        emit_event_if_rules('identity.federation.authorize.succeeded', company, payload)


def emit_backchannel_logout_sent(*, user, client_id: str) -> None:
    if not is_global():
        return
    payload = _user_payload(user, client_id)
    for company in _companies(user):
        emit_event_if_rules('identity.federation.backchannel_logout.sent', company, payload)


def _companies(user):
    return Company.objects.filter(
        memberships__user=user,
        memberships__is_enabled=True,
    ).distinct()


def _user_payload(user, client_id: str) -> dict:
    return {
        'user_id': user.pk,
        'email': user.email or '',
        'client_id': client_id,
        'source': 'federation',
    }
