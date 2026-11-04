"""Redirect URI validation for MCP dynamic client registration and authorize.

Rules (no exceptions):
- absolute https URL, or http on a loopback host (127.0.0.1, localhost, ::1);
- no other scheme (javascript:, data:, custom app schemes …);
- no fragment and no user info;
- authorize compares the value to the registered list exactly, with no wildcards.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from django.http import HttpRequest

MAX_MCP_REDIRECT_URIS = 16
MAX_MCP_REDIRECT_URI_LENGTH = 500
_LOOPBACK_HOSTS = ('127.0.0.1', 'localhost', '::1')


def validate_mcp_redirect_uri(request: HttpRequest | None, raw: str) -> tuple[str | None, str | None]:
    """Return (redirect_uri, None) when allowed, else (None, error). The value is not rewritten."""
    del request
    s = str(raw or '').strip()
    if not s:
        return None, 'Empty redirect_uri.'
    if len(s) > MAX_MCP_REDIRECT_URI_LENGTH:
        return None, 'redirect_uri is too long.'
    if any(ch in s for ch in ('\n', '\r', '\0', ' ', '\\')):
        return None, 'Invalid redirect_uri.'
    if '#' in s:
        return None, 'redirect_uri must not include a fragment.'
    try:
        parsed = urlsplit(s)
    except ValueError:
        return None, 'Invalid redirect_uri.'
    scheme = (parsed.scheme or '').lower()
    if scheme not in ('http', 'https'):
        return None, 'redirect_uri must use https, or http on a loopback address.'
    if parsed.scheme != scheme:
        return None, 'Invalid redirect_uri.'
    if not parsed.netloc or not parsed.hostname:
        return None, 'Invalid redirect_uri.'
    if parsed.username is not None or parsed.password is not None or '@' in parsed.netloc:
        return None, 'Invalid redirect_uri.'
    try:
        parsed.port
    except ValueError:
        return None, 'Invalid redirect_uri.'
    host = parsed.hostname.lower()
    if scheme == 'http' and host not in _LOOPBACK_HOSTS:
        return None, 'redirect_uri must use https, or http on a loopback address.'
    return s, None


def redirect_uri_host(uri: str) -> str:
    """Host (and port when set) shown to the user before sign-in and on consent."""
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return ''
    return parsed.netloc.lower()


def normalize_mcp_redirect_uris(request: HttpRequest, uris: list) -> tuple[list[str] | None, str | None]:
    if not isinstance(uris, list) or not uris:
        return None, 'invalid_redirect_uris'
    if len(uris) > MAX_MCP_REDIRECT_URIS:
        return None, 'too_many_redirect_uris'
    normalized: list[str] = []
    seen: set[str] = set()
    for item in uris:
        if not isinstance(item, str):
            return None, 'invalid_redirect_uris'
        url, err = validate_mcp_redirect_uri(request, item)
        if err or not url:
            return None, 'invalid_redirect_uris'
        if url in seen:
            continue
        seen.add(url)
        normalized.append(url)
    if not normalized:
        return None, 'invalid_redirect_uris'
    return normalized, None
