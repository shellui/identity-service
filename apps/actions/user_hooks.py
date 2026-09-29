"""Account lifecycle action events (OAuth signup, admin delete — not SCIM access)."""

from __future__ import annotations

from apps.actions.emit import emit_event_if_rules
from apps.actions.identity_payloads import user_event_payload


def emit_oauth_user_created_if_new(
    company,
    user,
    *,
    created: bool,
    oauth_provider: str,
) -> None:
    if not created:
        return
    payload = user_event_payload(user, source='oauth')
    payload['oauth_provider'] = oauth_provider
    emit_event_if_rules('identity.user.created', company, payload)


def emit_user_account_created(company, user, *, source: str) -> None:
    emit_event_if_rules(
        'identity.user.created',
        company,
        user_event_payload(user, source=source),
    )


def emit_user_account_deleted(company, user, *, source: str) -> None:
    emit_event_if_rules(
        'identity.user.deleted',
        company,
        user_event_payload(user, source=source),
    )


def emit_user_deleted_for_all_companies(user, *, source: str) -> None:
    memberships = user.company_memberships.select_related('company').order_by('company_id')
    for membership in memberships:
        emit_user_account_deleted(membership.company, user, source=source)
