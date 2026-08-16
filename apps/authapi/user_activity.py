"""Per-user last_seen_at for activity tracking (OAuth login, admin session login, token refresh)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.core.cache import cache
from django.db import DatabaseError, OperationalError
from django.utils import timezone

from .models import UserActivity

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser

logger = logging.getLogger(__name__)

# Avoid writing on every token refresh (SQLite locks easily under concurrent writes).
_TOUCH_THROTTLE_SECONDS = 60


def touch_user_last_seen(user: AbstractBaseUser) -> None:
    """Upsert UserActivity.last_seen_at to now (used for MAU and product analytics).

    Best-effort: DB lock / write failures must not break login or token refresh.
    """
    cache_key = f'authapi:last_seen_touch:{user.pk}'
    if cache.get(cache_key):
        return

    try:
        UserActivity.objects.update_or_create(
            user=user,
            defaults={'last_seen_at': timezone.now()},
        )
        cache.set(cache_key, 1, timeout=_TOUCH_THROTTLE_SECONDS)
    except (OperationalError, DatabaseError) as exc:
        # Common with SQLite when refresh storms or other writers hold the lock.
        logger.warning('touch_user_last_seen skipped for user_id=%s: %s', user.pk, exc)
