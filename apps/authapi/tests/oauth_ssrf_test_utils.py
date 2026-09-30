"""Test helpers to pin OAuth HTTP to local TLS servers without disabling SSRF checks globally."""

from __future__ import annotations

from contextlib import contextmanager, ExitStack
from urllib.parse import urlparse
from unittest.mock import patch

from apps.actions.ssrf import ResolvedWebhookEndpoint


def _endpoint_for_localhost(url: str, *, port_map: dict[str, int]) -> ResolvedWebhookEndpoint:
    parsed = urlparse(url)
    hostname = (parsed.hostname or '').lower()
    port = parsed.port or port_map.get(hostname) or (443 if parsed.scheme == 'https' else 80)
    connect_host = '127.0.0.1'
    host_header = hostname if not parsed.port else f'{hostname}:{parsed.port}'
    path = parsed.path or '/'
    if parsed.query:
        path = f'{path}?{parsed.query}'
    return ResolvedWebhookEndpoint(
        original_url=url,
        scheme=parsed.scheme or 'https',
        connect_host=connect_host,
        port=port,
        host_header=host_header,
        path=path,
    )


@contextmanager
def pin_oauth_http_to_localhost(*host_ports: tuple[str, int]):
    from apps.actions.ssrf import resolve_webhook_endpoint as _original_resolve

    port_map = {host.lower(): port for host, port in host_ports}

    def _resolve(url: str, *, allow_private: bool = False) -> ResolvedWebhookEndpoint:
        hostname = (urlparse(url).hostname or '').lower()
        if hostname in port_map:
            return _endpoint_for_localhost(url, port_map=port_map)
        return _original_resolve(url, allow_private=allow_private)

    targets = (
        'apps.actions.ssrf.resolve_webhook_endpoint',
        'apps.authapi.oauth_pinned_http.resolve_webhook_endpoint',
        'apps.authapi.oauth_safe_http.resolve_webhook_endpoint',
    )
    with ExitStack() as stack:
        for target in targets:
            stack.enter_context(patch(target, side_effect=_resolve))
        yield
