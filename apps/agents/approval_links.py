"""Signed links for the MCP approval page."""

from __future__ import annotations

from django.core.signing import BadSignature, SignatureExpired, TimestampSigner

_SIGNER_SALT = 'shellui-mcp-approval-fallback-v1'
APPROVAL_RETURN_SESSION_KEY = 'mcp_approval_return_path'
APPROVAL_PAGE_PREFIX = '/oauth/mcp/approval/'


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


def approval_return_path(approval_id: str, token: str) -> str:
    return f'{APPROVAL_PAGE_PREFIX}{approval_id}?token={token}'


def public_identity_origin(request=None) -> str:
    """Public identity origin for this region (``JWT_ISSUER``)."""
    from django.core.exceptions import ImproperlyConfigured

    from apps.authapi.magic_link import identity_public_base_url

    fallback = None
    if request is not None:
        fallback = request.build_absolute_uri('/')
    try:
        return identity_public_base_url(fallback=fallback).rstrip('/')
    except ImproperlyConfigured:
        return (fallback or '').rstrip('/')


def approval_link(approval_id: str, *, request=None) -> dict[str, str]:
    """Relative path and absolute page URL for one approval.

    Both include a fresh signed token. The token opens the page. It does not
    replace the browser session.
    """
    token = sign_approval_fallback_token(str(approval_id))
    path = approval_return_path(str(approval_id), token)
    origin = public_identity_origin(request)
    url = f'{origin}{path}' if origin else path
    return {'fallback_path': path, 'approval_url': url}
