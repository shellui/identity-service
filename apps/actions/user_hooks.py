"""Account lifecycle action events (OAuth signup, admin delete, profile updates)."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

from django.contrib.auth import get_user_model

from apps.actions.emit import emit_event_if_rules
from apps.actions.identity_payloads import user_event_payload

# Public names in ``changed_fields``. ``groups`` is the direct CompanyGroup id set.
_PROFILE_FIELDS = (
    'name',
    'email',
    'username',
    'avatar_url',
    'language',
    'region',
    'active',
    'is_active',
    'groups',
    'role',
)

_user_update_source: ContextVar[str | None] = ContextVar('identity_user_update_source', default=None)


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


@contextmanager
def user_profile_event_source(source: str):
    """Mark Django admin membership saves so they emit ``identity.user.updated``."""
    token = _user_update_source.set(source)
    try:
        yield
    finally:
        _user_update_source.reset(token)


def current_user_profile_event_source() -> str | None:
    return _user_update_source.get()


def profile_snapshot(user, company) -> dict:
    """Tracked profile fields for one company. Avatar is the explicit cached URL only."""
    from django.core.cache import cache

    from apps.authapi.models import UserPreference
    from apps.companies.access import is_company_access_enabled

    name = (user.get_full_name() or '').strip()
    email = (getattr(user, 'email', None) or '').strip().lower()
    username = (getattr(user, 'username', None) or '').strip()
    language = UserPreference.LANGUAGE_EN
    region = 'UTC'
    avatar_url = None
    groups: tuple[int, ...] = ()
    role = 'member'
    active = False
    if getattr(user, 'pk', None) and getattr(company, 'pk', None):
        prefs = UserPreference.objects.filter(user_id=user.pk).values_list('language', 'region').first()
        if prefs:
            language, region = prefs
        cached = cache.get(f'shellui:user_metadata:{user.pk}')
        if isinstance(cached, dict):
            raw_avatar = cached.get('avatar_url')
            if isinstance(raw_avatar, str) and raw_avatar.strip():
                avatar_url = raw_avatar.strip()
        groups = tuple(sorted(user.company_groups.filter(company_id=company.pk).values_list('pk', flat=True)))
        if company.owners.filter(pk=user.pk).exists():
            role = 'owner'
        active = is_company_access_enabled(company, user)
    return {
        'name': name,
        'email': email,
        'username': username,
        'avatar_url': avatar_url,
        'language': language,
        'region': region,
        'active': active,
        'is_active': bool(getattr(user, 'is_active', True)),
        'groups': groups,
        'role': role,
    }


def snapshot_profiles_for_ids(company, user_ids) -> dict[int, dict]:
    User = get_user_model()
    ids = [pk for pk in {int(pk) for pk in user_ids} if pk]
    if not ids:
        return {}
    return {user.pk: profile_snapshot(user, company) for user in User.objects.filter(pk__in=ids)}


def snapshot_user_companies(user) -> dict[int, tuple]:
    """``{company_id: (company, snapshot)}`` for each membership, read from the database."""
    if not getattr(user, 'pk', None):
        return {}
    stored = get_user_model().objects.get(pk=user.pk)
    out: dict[int, tuple] = {}
    for membership in stored.company_memberships.select_related('company'):
        out[membership.company_id] = (membership.company, profile_snapshot(stored, membership.company))
    return out


def emit_user_updated_if_changed(company, user, *, source: str, before: dict) -> None:
    """Emit ``identity.user.updated`` when a tracked field differs from ``before``."""
    if not getattr(user, 'pk', None) or not getattr(company, 'pk', None) or not before:
        return
    user.refresh_from_db()
    after = profile_snapshot(user, company)
    changed = [name for name in _PROFILE_FIELDS if before.get(name) != after.get(name)]
    if not changed:
        return
    payload = user_event_payload(user, source=source)
    payload.update(
        {
            'name': after['name'] or None,
            'active': after['active'],
            'is_active': after['is_active'],
            'role': after['role'],
            'group_ids': list(after['groups']),
            'avatar_url': after['avatar_url'],
            'changed_fields': changed,
        }
    )
    emit_event_if_rules('identity.user.updated', company, payload)


def emit_profile_snapshots(company, befores: dict[int, dict], *, source: str) -> None:
    if not befores:
        return
    User = get_user_model()
    for user in User.objects.filter(pk__in=list(befores)):
        before = befores.get(user.pk)
        if before is not None:
            emit_user_updated_if_changed(company, user, source=source, before=before)


def emit_user_company_snapshots(user, befores: dict[int, tuple], *, source: str) -> None:
    for company, before in befores.values():
        emit_user_updated_if_changed(company, user, source=source, before=before)
