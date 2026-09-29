"""SSRF-pinned HTTP for OAuth (TLS SNI to original hostname, TCP to resolved IP)."""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

from apps.actions.ssrf import SSRFError, resolve_webhook_endpoint
from apps.actions.webhook_transport import fetch_resolved_endpoint


def _resolve_chain(url: str) -> str:
    return resolve_webhook_endpoint(url, allow_private=False).original_url


def pinned_fetch_bytes(
    url: str,
    *,
    method: str = 'GET',
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: float = 20,
    max_redirects: int = 5,
    max_bytes: int = 512 * 1024,
) -> tuple[int, dict[str, str], bytes]:
    current = _resolve_chain(url)
    redirects = 0
    while True:
        endpoint = resolve_webhook_endpoint(current, allow_private=False)
        status, resp_headers, payload = fetch_resolved_endpoint(
            endpoint,
            method=method,
            headers=headers,
            body=body,
            timeout=timeout,
            max_bytes=max_bytes,
        )
        if status in {301, 302, 303, 307, 308}:
            redirects += 1
            if redirects > max_redirects:
                raise SSRFError('Too many redirects.')
            location = resp_headers.get('location', '')
            if not location:
                raise SSRFError('Redirect response missing Location header.')
            parsed = urlparse(location)
            if parsed.scheme in {'http', 'https'} and parsed.netloc:
                target = location
            else:
                target = urljoin(current, location)
            current = _resolve_chain(target)
            continue
        if len(payload) > max_bytes:
            raise SSRFError('OAuth HTTP response is too large.')
        return status, resp_headers, payload


def pinned_get_json(
    url: str,
    *,
    headers: dict | None = None,
    timeout: float = 20,
    max_redirects: int = 5,
    max_bytes: int = 512 * 1024,
) -> dict:
    status, _, payload = pinned_fetch_bytes(
        url,
        headers=headers,
        timeout=timeout,
        max_redirects=max_redirects,
        max_bytes=max_bytes,
    )
    if status >= 400:
        raise SSRFError(f'OAuth HTTP request failed with status {status}.')
    data = json.loads(payload.decode('utf-8', errors='replace'))
    if not isinstance(data, dict):
        raise SSRFError('OAuth HTTP response must be a JSON object.')
    return data


class _PinnedEndpointAdapter(HTTPAdapter):
    """Route urllib3 connections through pinned fetch (one request per adapter mount)."""

    def __init__(self, *, original_url: str, **kwargs):
        self._original_url = original_url
        super().__init__(**kwargs)

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        import io

        method = request.method or 'GET'
        body = request.body
        req_body = body.encode('utf-8') if isinstance(body, str) else body
        status, resp_headers, payload = pinned_fetch_bytes(
            request.url,
            method=method,
            headers=dict(request.headers),
            body=req_body if req_body else None,
            timeout=timeout if isinstance(timeout, (int, float)) else 20,
        )
        response = requests.Response()
        response.status_code = status
        response.headers.update(resp_headers)
        response.raw = io.BytesIO(payload)
        response._content = payload
        response.url = request.url
        response.request = request
        return response


def pinned_requests_session_for_url(url: str) -> requests.Session:
    cleaned = _resolve_chain(url)
    session = requests.Session()
    adapter = _PinnedEndpointAdapter(original_url=cleaned)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session
