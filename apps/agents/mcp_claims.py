"""Strict parsing of setup-related claims (JWT booleans and scalars)."""

from __future__ import annotations

from typing import Any

from apps.agents.json_strict import strict_non_negative_int


def strict_bool_claim(raw: object) -> bool:
    """True only for JSON boolean ``true`` (no string or numeric truthiness)."""
    return raw is True


def optional_non_negative_int(raw: object) -> int | None:
    """External JSON integers only: ``bool``, ``float``, and string numerics are rejected."""
    return strict_non_negative_int(raw)


def optional_int(raw: object) -> int | None:
    """Alias for :func:`optional_non_negative_int` (non-negative when present)."""
    return optional_non_negative_int(raw)
