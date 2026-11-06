"""Strict parsing of setup-related claims (JWT booleans and scalars)."""

from __future__ import annotations

from typing import Any


def strict_bool_claim(raw: object) -> bool:
    """True only for JSON boolean ``true`` (no string or numeric truthiness)."""
    return raw is True


def optional_int(raw: object) -> int | None:
    if raw is None or raw == '':
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None
