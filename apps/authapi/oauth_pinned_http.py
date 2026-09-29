"""HTTP session that connects to vetted IPs (mitigate DNS rebinding for OAuth fetches)."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

from apps.actions.ssrf import SSRFError, resolve_webhook_endpoint


class _PinnedHostAdapter(HTTPAdapter):
    def __init__(self, *, connect_host: str, host_header: str, **kwargs):
        self._connect_host = connect_host
        self._host_header = host_header
        super().__init__(**kwargs)

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        parsed = urlparse(request.url)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        pinned_url = f'{parsed.scheme}://{self._connect_host}:{port}{parsed.path or "/"}'
        if parsed.query:
            pinned_url = f'{pinned_url}?{parsed.query}'
        request.url = pinned_url
        request.headers['Host'] = self._host_header
        return super().send(
            request,
            stream=stream,
            timeout=timeout,
            verify=verify,
            cert=cert,
            proxies=proxies,
        )


def pinned_requests_session_for_url(url: str) -> requests.Session:
    endpoint = resolve_webhook_endpoint(url, allow_private=False)
    session = requests.Session()
    adapter = _PinnedHostAdapter(
        connect_host=endpoint.connect_host,
        host_header=endpoint.host_header,
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def pinned_get_json(
    url: str,
    *,
    headers: dict | None = None,
    timeout: float = 20,
    max_redirects: int = 5,
    max_bytes: int = 512 * 1024,
) -> dict:
    import json

    current = resolve_webhook_endpoint(url, allow_private=False).original_url
    redirects = 0
    while True:
        session = pinned_requests_session_for_url(current)
        response = session.get(
            current,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        if response.status_code in {301, 302, 303, 307, 308}:
            redirects += 1
            if redirects > max_redirects:
                raise SSRFError('Too many redirects.')
            location = response.headers.get('Location', '')
            if not location:
                raise SSRFError('Redirect response missing Location header.')
            parsed = urlparse(location)
            if parsed.scheme in {'http', 'https'} and parsed.netloc:
                target = location
            else:
                target = urljoin(current, location)
            current = resolve_webhook_endpoint(target, allow_private=False).original_url
            response.close()
            continue
        response.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise SSRFError('OAuth HTTP response is too large.')
            chunks.append(chunk)
        raw = b''.join(chunks).decode('utf-8', errors='replace')
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise SSRFError('OAuth HTTP response must be a JSON object.')
        return data
