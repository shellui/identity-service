"""Case-insensitive OAuth user lookup when duplicate email rows exist."""

from __future__ import annotations

import logging
import unicodedata

from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)
User = get_user_model()


def normalize_oauth_email(email: str) -> str:
    return unicodedata.normalize('NFKC', (email or '').strip()).casefold()


def get_or_create_user_for_oauth(*, email: str, defaults: dict) -> tuple[User, bool]:
    """
    Resolve a user by email without raising MultipleObjectsReturned.

    Matches are case-insensitive. When several rows share the same email, the lowest pk wins
    and a warning is logged so operators can run duplicate-email cleanup.
    """
    normalized = normalize_oauth_email(email)
    if not normalized:
        raise ValueError('OAuth email is required.')

    matches = list(User.objects.filter(email__iexact=normalized).order_by('pk')[:2])
    if len(matches) >= 2:
        logger.warning(
            'Multiple users share email %r (pks include %s and %s); OAuth will use pk=%s',
            normalized,
            matches[0].pk,
            matches[1].pk,
            matches[0].pk,
        )
    if matches:
        return matches[0], False

    create_defaults = {**defaults, 'email': normalized}
    return User.objects.create(**create_defaults), True
