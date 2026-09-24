"""Hard-delete user accounts (admin or self-service) with action events and session cleanup."""

from __future__ import annotations

from django.core.cache import cache
from django.utils import timezone

from apps.actions.user_hooks import emit_user_deleted_for_all_companies

from .models import PersonalAccessToken
from .refresh_sessions import revoke_all_refresh_sessions_for_user


def invalidate_user_auth_state(user) -> None:
    """Revoke refresh sessions and PAT rows so outstanding tokens stop working promptly."""
    revoke_all_refresh_sessions_for_user(user)
    PersonalAccessToken.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=timezone.now())
    cache.delete(f'shellui:user_metadata:{user.id}')


def delete_user_account(user, *, source: str) -> None:
    """
    Emit ``identity.user.deleted`` once per company membership, then remove the user row.

    Matches Django admin delete semantics (hard delete with cascading FKs).
    """
    invalidate_user_auth_state(user)
    emit_user_deleted_for_all_companies(user, source=source)
    user.delete()
