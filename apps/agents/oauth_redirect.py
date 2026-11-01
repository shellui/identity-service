"""Redirect URI validation for MCP dynamic client registration and authorize."""

from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest
from urllib.parse import urlsplit

from apps.companies.redirect_allowlist import (
    is_custom_scheme_redirect,
    is_loopback_redirect_url,
    loopback_oauth_redirects_allowed,
    normalize_client_redirect_url,
)

MAX_MCP_REDIRECT_URIS = 16


def validate_mcp_redirect_uri(request: HttpRequest, raw: str) -> tuple[str | None, str | None]:
    """
    Canonical redirect URI for MCP OAuth clients.
    Allows custom app schemes, loopback http(s) when permitted, and https elsewhere.
    Rejects relative paths (open redirect on the identity host).
    """
    s = (raw or '').strip()
    if not s:
        return None, 'Empty redirect_uri.'
    if s.startswith('/') or s.startswith('//'):
        return None, 'Invalid redirect_uri.'
    url, err = normalize_client_redirect_url(request, s)
    if err or not url:
        message = (err or 'Invalid redirect_uri.').replace('redirect_to', 'redirect_uri')
        return None, message
    if is_custom_scheme_redirect(url):
        return url, None
    if is_loopback_redirect_url(url):
        if not loopback_oauth_redirects_allowed():
            return None, 'redirect_uri is not allowed.'
        return url, None
    parsed = urlsplit(url)
    if parsed.scheme == 'http' and not settings.DEBUG:
        return None, 'redirect_uri must use https.'
    if parsed.scheme not in ('http', 'https'):
        return None, 'Invalid redirect_uri.'
    return url, None


def normalize_mcp_redirect_uris(request: HttpRequest, uris: list) -> tuple[list[str] | None, str | None]:
    if not isinstance(uris, list) or not uris:
        return None, 'invalid_redirect_uris'
    if len(uris) > MAX_MCP_REDIRECT_URIS:
        return None, 'too_many_redirect_uris'
    normalized: list[str] = []
    seen: set[str] = set()
    for item in uris:
        url, err = validate_mcp_redirect_uri(request, str(item))
        if err or not url:
            return None, 'invalid_redirect_uris'
        if url in seen:
            continue
        seen.add(url)
        normalized.append(url)
    if not normalized:
        return None, 'invalid_redirect_uris'
    return normalized, None
