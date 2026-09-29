"""OpenID Connect discovery document helpers."""

from __future__ import annotations

from apps.authapi.oauth_safe_http import safe_get_json


def discovery_url_for_server_url(server_url: str) -> str:
    base = str(server_url or '').strip().rstrip('/')
    if not base:
        return ''
    if base.endswith('openid-configuration'):
        return base
    return f'{base}/.well-known/openid-configuration'


def fetch_oidc_discovery(server_url: str) -> dict:
    url = discovery_url_for_server_url(server_url)
    if not url:
        return {}
    document = safe_get_json(url)
    return document if isinstance(document, dict) else {}
