"""Signed links for the MCP approval fallback page."""

from __future__ import annotations

from django.core.signing import BadSignature, SignatureExpired, TimestampSigner

_SIGNER_SALT = 'shellui-mcp-approval-fallback-v1'


def sign_approval_fallback_token(approval_id: str) -> str:
    return TimestampSigner(salt=_SIGNER_SALT).sign(str(approval_id))


def verify_approval_fallback_token(token: str, *, max_age_seconds: int) -> str:
    if max_age_seconds <= 0:
        raise SignatureExpired('expired')
    return TimestampSigner(salt=_SIGNER_SALT).unsign(token, max_age=max_age_seconds)


def parse_fallback_token(token: str, *, max_age_seconds: int) -> str | None:
    try:
        return verify_approval_fallback_token(token, max_age_seconds=max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
