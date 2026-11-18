"""One-time MCP authorization codes (stored hashed, never logged)."""

from __future__ import annotations

import hashlib
import hmac
import secrets


def issue_mcp_authorization_code() -> tuple[str, str]:
    """Return (plaintext code for redirect, digest for storage)."""
    plain = secrets.token_urlsafe(32)
    return plain, hash_authorization_code(plain)


def hash_authorization_code(code: str) -> str:
    return hashlib.sha256((code or '').encode('utf-8')).hexdigest()


def authorization_codes_match(stored_digest: str, presented: str) -> bool:
    expected = hash_authorization_code(presented)
    if len(expected) != len(stored_digest):
        return False
    return hmac.compare_digest(expected, stored_digest)
