"""Strict parsing of setup-related claims (JWT booleans and scalars)."""

from __future__ import annotations

from typing import Any


def strict_bool_claim(raw: object) -> bool:
    """True only for ``bool`` True or case-insensitive string ``true`` (ai-service / identity-issued)."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() == 'true'
    return False


def optional_int(raw: object) -> int | None:
    if raw is None or raw == '':
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None
