"""Create a local account without staff flags."""

from __future__ import annotations

import uuid

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction

User = get_user_model()


def create_unprivileged_user(*, email: str, full_name: str = ''):
    """New user with ``is_staff`` and ``is_superuser`` false. Those fields are not arguments."""
    first, last = _split_name(full_name)
    for _attempt in range(5):
        user = User(
            username=_unique_username(email),
            email=email,
            first_name=first,
            last_name=last,
            is_staff=False,
            is_superuser=False,
            is_active=True,
        )
        user.set_unusable_password()
        try:
            with transaction.atomic():
                user.save()
        except IntegrityError:
            continue
        user.refresh_from_db()
        return user
    user = User(
        username=f'user{uuid.uuid4().hex[:12]}',
        email=email,
        first_name=first,
        last_name=last,
        is_staff=False,
        is_superuser=False,
        is_active=True,
    )
    user.set_unusable_password()
    user.save()
    return user


def _split_name(full_name: str) -> tuple[str, str]:
    parts = (full_name or '').strip().split(' ', 1)
    if not parts or not parts[0]:
        return '', ''
    first = parts[0][:150]
    last = parts[1][:150] if len(parts) > 1 else ''
    return first, last


def _unique_username(email: str) -> str:
    local = email.split('@', 1)[0].split('+', 1)[0]
    cleaned = ''.join(ch for ch in local if ch.isalnum() or ch in '._-')[:30] or 'user'
    candidate = cleaned
    suffix = 0
    while User.objects.filter(username=candidate).exists():
        suffix += 1
        candidate = f'{cleaned[:20]}{suffix}'
    return candidate
