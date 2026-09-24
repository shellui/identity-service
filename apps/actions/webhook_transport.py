"""HTTP(S) POST to a pre-resolved webhook endpoint (SSRF-safe connect)."""

from __future__ import annotations

import ssl
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse

from apps.actions.ssrf import ResolvedWebhookEndpoint, SSRFError, resolve_webhook_endpoint


class WebhookHTTPError(Exception):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def post_resolved_webhook(
    endpoint: ResolvedWebhookEndpoint,
    *,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
) -> HTTPResponse:
    req_headers = dict(headers)
    req_headers['Host'] = endpoint.host_header
    if endpoint.scheme == 'https':
        context = ssl.create_default_context()
        conn: HTTPConnection | HTTPSConnection = HTTPSConnection(
            endpoint.connect_host,
            endpoint.port,
            timeout=timeout,
            context=context,
            server_hostname=endpoint.host_header.split(':')[0],
        )
    else:
        conn = HTTPConnection(endpoint.connect_host, endpoint.port, timeout=timeout)
    try:
        conn.request('POST', endpoint.path, body=body, headers=req_headers)
        return conn.getresponse()
    finally:
        conn.close()


def post_webhook_url(
    url: str,
    *,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
    allow_private: bool,
) -> int:
    try:
        endpoint = resolve_webhook_endpoint(url, allow_private=allow_private)
    except SSRFError as exc:
        raise WebhookHTTPError(str(exc)) from exc
    response = post_resolved_webhook(endpoint, body=body, headers=headers, timeout=timeout)
    status = int(response.status)
    response.read()
    return status
