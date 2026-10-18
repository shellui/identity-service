"""Parse instance-role settings. Safe to import while Django settings load."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

ROLE_GLOBAL = 'global'
ROLE_REGION = 'region'

# Built-in hosts a relying-party deployment must replace before production start.
DEFAULT_FORBIDDEN_HOSTS = frozenset({'email.shellui.com', 'admin.shellui.com'})


def parse_instance_role(raw: str | None) -> str:
    """Return ``global``, ``region``, or ``''`` (standalone)."""
    value = (raw or '').strip().lower()
    if not value:
        return ''
    if value in {ROLE_GLOBAL, ROLE_REGION}:
        return value
    raise ImproperlyConfigured(
        'SHELLUI_INSTANCE_ROLE must be "global", "region", or unset. '
        f'Got: {value!r}'
    )


def parse_origin_list(raw: str | None) -> list[str]:
    origins: list[str] = []
    for item in (raw or '').split(','):
        origin = item.strip().rstrip('/')
        if not origin:
            continue
        parts = urlsplit(origin)
        if parts.scheme not in {'http', 'https'} or not parts.netloc or parts.path not in {'', '/'}:
            raise ImproperlyConfigured(
                'OIDC_CORS_ALLOWED_ORIGINS entries must be origins like https://app.example.com. '
                f'Got: {origin!r}'
            )
        if origin not in origins:
            origins.append(origin)
    return origins


def parse_oidc_clients(raw: str | None, *, allow_http: bool) -> list[dict]:
    """JSON list of confidential clients. Empty when unset."""
    text = (raw or '').strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImproperlyConfigured('OIDC_CLIENTS must be a JSON list.') from exc
    if not isinstance(data, list):
        raise ImproperlyConfigured('OIDC_CLIENTS must be a JSON list.')
    clients: list[dict] = []
    seen: set[str] = set()
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ImproperlyConfigured(f'OIDC_CLIENTS[{index}] must be an object.')
        client_id = str(item.get('client_id') or '').strip()
        secret = str(item.get('client_secret') or '')
        redirects = item.get('redirect_uris')
        logout = str(item.get('backchannel_logout_uri') or '').strip()
        if not client_id or not secret or not isinstance(redirects, list) or not redirects:
            raise ImproperlyConfigured(
                f'OIDC_CLIENTS[{index}] needs client_id, client_secret, and redirect_uris.'
            )
        if client_id in seen:
            raise ImproperlyConfigured(f'Duplicate OIDC client_id {client_id!r}.')
        seen.add(client_id)
        clean_redirects: list[str] = []
        for uri in redirects:
            clean_redirects.append(_https_url(str(uri), allow_http=allow_http, label='redirect_uri'))
        logout_uri = ''
        if logout:
            logout_uri = _https_url(logout, allow_http=allow_http, label='backchannel_logout_uri')
        clients.append(
            {
                'client_id': client_id,
                'client_secret': secret,
                'redirect_uris': clean_redirects,
                'backchannel_logout_uri': logout_uri,
            }
        )
    return clients


def parse_jwks(raw: str | None) -> dict:
    text = (raw or '').strip()
    if not text:
        return {'keys': []}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImproperlyConfigured('GLOBAL_JWKS must be a JSON JWKS document.') from exc
    if not isinstance(data, dict) or not isinstance(data.get('keys'), list):
        raise ImproperlyConfigured('GLOBAL_JWKS must be a JSON object with a keys array.')
    return data


def hostname_of(url: str) -> str:
    return (urlsplit((url or '').strip()).hostname or '').lower().rstrip('.')


def region_startup_errors(
    *,
    role: str,
    debug: bool,
    email_service_url: str,
    csrf_trusted_origins: list[str],
    allowed_hosts: list[str],
    issuer_url: str,
    jwks: dict,
    client_id: str,
    client_secret: str,
    jwt_issuer: str | None,
) -> list[str]:
    """Problems that stop a relying-party process in production. Empty otherwise."""
    if debug or role != ROLE_REGION:
        return []
    errors: list[str] = []
    hosts: list[tuple[str, str]] = [('EMAIL_SERVICE_URL', hostname_of(email_service_url))]
    for origin in csrf_trusted_origins:
        hosts.append(('CSRF_TRUSTED_ORIGINS', hostname_of(origin)))
    for host in allowed_hosts:
        hosts.append(('ALLOWED_HOSTS', (host or '').strip().lower().rstrip('.')))
    found = sorted({host for _label, host in hosts if host in DEFAULT_FORBIDDEN_HOSTS})
    if found:
        errors.append(
            'SHELLUI_INSTANCE_ROLE=region cannot use the built-in hosts '
            + ', '.join(found)
            + '. Set this deployment\'s own email, admin, and allowed hosts.'
        )
    if not (issuer_url or '').strip():
        errors.append('GLOBAL_ISSUER_URL is required when SHELLUI_INSTANCE_ROLE=region.')
    keys = jwks.get('keys') if isinstance(jwks, dict) else None
    if not keys:
        errors.append('GLOBAL_JWKS is required when SHELLUI_INSTANCE_ROLE=region.')
    if not (client_id or '').strip() or not (client_secret or '').strip():
        errors.append(
            'GLOBAL_CLIENT_ID and GLOBAL_CLIENT_SECRET are required when SHELLUI_INSTANCE_ROLE=region.'
        )
    if not (jwt_issuer or '').strip():
        errors.append('JWT_ISSUER is required when SHELLUI_INSTANCE_ROLE=region.')
    return errors


def _https_url(value: str, *, allow_http: bool, label: str) -> str:
    url = value.strip()
    parts = urlsplit(url)
    schemes = {'https', 'http'} if allow_http else {'https'}
    if parts.scheme not in schemes or not parts.netloc:
        allowed = 'https (http allowed when DEBUG=true)' if allow_http else 'https'
        raise ImproperlyConfigured(f'OIDC {label} must be an {allowed} URL. Got: {url!r}')
    return url
