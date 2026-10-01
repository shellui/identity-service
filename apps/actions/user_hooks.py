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


def _actor_email(actor) -> str | None:
    return ((getattr(actor, 'email', None) or '').strip() or None) if actor is not None else None


def invitation_event_payload(invitation) -> dict:
    """No ``user_id``: the invitee may not have an account yet, and must not reveal accounts in other companies."""
    return {
        'invitation_id': invitation.pk,
        'email': invitation.email,
        'language': invitation.language,
        'invited_by': _actor_email(invitation.invited_by),
        'invitation_url': invitation.app_url or None,
        'source': 'invitation',
    }


def emit_user_invited(invitation) -> list:
    """Emit ``identity.user.invited``; returns queued outbox rows (empty without an enabled rule)."""
    return emit_event_if_rules('identity.user.invited', invitation.company, invitation_event_payload(invitation))


def emit_user_invitation_revoked(invitation) -> None:
    payload = invitation_event_payload(invitation)
    payload['revoked_by'] = _actor_email(invitation.revoked_by)
    emit_event_if_rules('identity.user.invitation_revoked', invitation.company, payload)


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
