"""Block webhook URLs that target private or link-local addresses (SSRF)."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class SSRFError(ValueError):
    pass


def validate_webhook_url(url: str, *, allow_private: bool = False) -> str:
    parsed = urlparse((url or '').strip())
    if parsed.scheme not in {'http', 'https'}:
        raise SSRFError('Webhook URL must use http or https.')
    if not parsed.hostname:
        raise SSRFError('Webhook URL must include a hostname.')
    host = parsed.hostname.lower()
    if host in {'localhost', 'metadata.google.internal'}:
        if not allow_private:
            raise SSRFError('Localhost webhook URLs are not allowed.')
        return url
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            if not allow_private:
                raise SSRFError('Private or link-local webhook URLs are not allowed.')
        return url
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == 'https' else 80))
    except socket.gaierror as exc:
        raise SSRFError(f'Could not resolve webhook hostname: {host}') from exc
    if not allow_private:
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise SSRFError('Webhook hostname resolves to a private or link-local address.')
    return url
