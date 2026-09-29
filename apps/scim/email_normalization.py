"""Normalize and validate emails received over SCIM."""

from __future__ import annotations

import unicodedata

from django_scim import exceptions

SCIM_EMAIL_INVALID_DETAIL = 'Primary email local part must use ASCII characters only.'


def normalize_scim_email(email: str) -> str:
    """NFKC plus lowercase, trimmed. Used when persisting SCIM user emails."""
    return unicodedata.normalize('NFKC', (email or '').strip()).casefold()


def assert_scim_email_local_part_ascii(email: str) -> None:
    """Reject non-ASCII local parts before storage (SCIM clients must send ASCII)."""
    normalized = normalize_scim_email(email)
    if not normalized or '@' not in normalized:
        return
    local, _sep, _domain = normalized.partition('@')
    if not local.isascii():
        raise exceptions.BadRequestError(SCIM_EMAIL_INVALID_DETAIL)
