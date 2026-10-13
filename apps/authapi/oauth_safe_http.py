"""SSRF-safe HTTP for OAuth provider discovery and userinfo fetches."""

from __future__ import annotations

from apps.actions.ssrf import SSRFError, resolve_webhook_endpoint
from apps.authapi.oauth_pinned_http import pinned_get_json, pinned_requests_session_for_url

MAX_OAUTH_FETCH_BYTES = 512 * 1024
MAX_REDIRECTS = 5


def assert_public_http_url(url: str) -> str:
    cleaned = (url or '').strip()
    if not cleaned:
        raise SSRFError('URL is required.')
    resolve_webhook_endpoint(cleaned, allow_private=False)
    return cleaned


def safe_get_json(
    url: str,
    *,
    headers: dict | None = None,
    timeout: float = 20,
) -> dict:
    """GET JSON from a public URL; block private targets and pin the resolved IP."""
    assert_public_http_url(url)
    return pinned_get_json(
        url,
        headers=headers,
        timeout=timeout,
        max_redirects=MAX_REDIRECTS,
        max_bytes=MAX_OAUTH_FETCH_BYTES,
    )


def oauth_requests_session_for_url(url: str):
    """Pinned ``requests.Session`` for OAuth token, userinfo, and JWKS fetches."""
    cleaned = assert_public_http_url(url)
    return pinned_requests_session_for_url(cleaned)
