"""Strict JSON scalar parsing for internal MCP APIs (no bool-as-int, no string numerics)."""

from __future__ import annotations

import base64
import json

import jwt
from typing import Any


def strict_non_negative_int(raw: Any) -> int | None:
    """JSON integers only: ``bool`` and subclasses of ``int`` are rejected."""
    if raw is None or raw == '':
        return None
    if isinstance(raw, bool) or type(raw) is not int:
        return None
    if raw < 0:
        return None
    return raw


def strict_json_int_for_company_id(raw: Any) -> int | None:
    """Company id from JSON: must be ``int`` (``bool`` rejected). ``0`` allowed for global placeholder flows."""
    return strict_non_negative_int(raw)


def strict_positive_company_id_for_oauth_form(raw: Any) -> int | None:
    """Regional id for OAuth token bodies: JSON positive int, or form urlencoded digit-only string.

    Rejects bools, floats, signed numbers, and strings with non-digits (no silent coercion).
    """
    if raw is None or raw == '':
        return None
    if isinstance(raw, bool):
        return None
    if type(raw) is int:
        if raw <= 0:
            return None
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        if not text.isdigit():
            return None
        value = int(text)
        if value <= 0:
            return None
        return value
    return None


_ALL_DECODE_ALGOS = (
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
    'ES256',
    'ES384',
    'ES512',
    'PS256',
    'PS384',
    'PS512',
    'EdDSA',
)


def decode_jwt_payload_unverified(segment: str) -> dict[str, Any] | None:
    """Parse JWT payload JSON without signature verification (peer routing only)."""
    s = segment.strip()
    if not s or s.count('.') != 2:
        return None
    try:
        out = jwt.decode(
            s,
            options={'verify_signature': False, 'verify_exp': False},
            algorithms=list(_ALL_DECODE_ALGOS),
        )
        if isinstance(out, dict):
            return out
    except (jwt.PyJWTError, ValueError, TypeError):
        pass
    try:
        payload_b64 = s.split('.', 2)[1]
        pad = '=' * (-len(payload_b64) % 4)
        raw = base64.urlsafe_b64decode(payload_b64 + pad)
        out = json.loads(raw.decode('utf-8'))
        return out if isinstance(out, dict) else None
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return None
