"""Company-scoped SCIM bearer token generation and verification."""

from __future__ import annotations

import hashlib
import secrets


def generate_scim_token() -> tuple[str, str, str]:
    """
    Return ``(full_token, prefix, sha256_hex)``.

    The prefix is stored for admin display and indexed lookup; only the hash is persisted.
    """
    raw = secrets.token_urlsafe(32)
    prefix = raw[:12]
    digest = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    return raw, prefix, digest


def hash_scim_token(raw: str) -> str:
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()
