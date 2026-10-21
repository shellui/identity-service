"""Which job this process is doing. Unset means standalone."""

from __future__ import annotations

from django.conf import settings

from apps.federation.parsing import ROLE_GLOBAL, ROLE_REGION


def instance_role() -> str:
    return getattr(settings, 'SHELLUI_INSTANCE_ROLE', '') or ''


def is_global() -> bool:
    return instance_role() == ROLE_GLOBAL


def is_region() -> bool:
    return instance_role() == ROLE_REGION
