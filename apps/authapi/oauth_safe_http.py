"""SSRF-safe HTTP for OAuth provider discovery and userinfo fetches."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

import requests
from requests import Response

from apps.actions.ssrf import SSRFError, resolve_webhook_endpoint

MAX_OAUTH_FETCH_BYTES = 512 * 1024
MAX_REDIRECTS = 5


def assert_public_http_url(url: str) -> str:
    cleaned = (url or '').strip()
    if not cleaned:
        raise SSRFError('URL is required.')
    resolve_webhook_endpoint(cleaned, allow_private=False)
    return cleaned


def _validate_redirect_location(current_url: str, location: str) -> str:
    if not location:
        raise SSRFError('Redirect response missing Location header.')
    parsed = urlparse(location)
    if parsed.scheme in {'http', 'https'} and parsed.netloc:
        target = location
    else:
        target = urljoin(current_url, location)
    return assert_public_http_url(target)


def safe_get_json(
    url: str,
    *,
    headers: dict | None = None,
    timeout: float = 20,
) -> dict:
    """GET JSON from a public URL; block private targets and unsafe redirects."""
    current = assert_public_http_url(url)
    session = requests.Session()
    redirects = 0
    while True:
        response = session.get(
            current,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        if response.status_code in {301, 302, 303, 307, 308}:
            redirects += 1
            if redirects > MAX_REDIRECTS:
                raise SSRFError('Too many redirects.')
            location = response.headers.get('Location', '')
            current = _validate_redirect_location(current, location)
            response.close()
            continue
        response.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_OAUTH_FETCH_BYTES:
                raise SSRFError('OAuth discovery response is too large.')
            chunks.append(chunk)
        raw = b''.join(chunks).decode('utf-8', errors='replace')
        import json

        data = json.loads(raw)
        if not isinstance(data, dict):
            raise SSRFError('OAuth discovery response must be a JSON object.')
        return data


def validate_oidc_discovery_document(document: dict) -> None:
    for key in (
        'authorization_endpoint',
        'token_endpoint',
        'userinfo_endpoint',
        'jwks_uri',
    ):
        value = document.get(key)
        if isinstance(value, str) and value.strip():
            assert_public_http_url(value.strip())
