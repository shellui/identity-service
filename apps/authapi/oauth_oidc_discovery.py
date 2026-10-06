"""OpenID Connect discovery document helpers."""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from apps.actions.ssrf import SSRFError
from apps.authapi.oauth_errors import OAuthProviderResponseError
from apps.authapi.oauth_safe_http import assert_public_http_url, safe_get_json

WELL_KNOWN_OPENID_CONFIGURATION = '/.well-known/openid-configuration'


def oidc_issuer_for_server_url(server_url: str) -> str:
    """Issuer the discovery document for ``server_url`` must publish (OIDC Discovery 4.3).

    Accepts the issuer URL or ``{issuer}/.well-known/openid-configuration``. Any other
    ``/.well-known/`` path has no derivable issuer and returns an empty string.
    """
    base = str(server_url or '').strip().rstrip('/')
    if base.endswith(WELL_KNOWN_OPENID_CONFIGURATION):
        base = base[: -len(WELL_KNOWN_OPENID_CONFIGURATION)].rstrip('/')
    if '/.well-known/' in f'{base}/':
        return ''
    return base


def discovery_url_for_server_url(server_url: str) -> str:
    issuer = oidc_issuer_for_server_url(server_url)
    if not issuer:
        return ''
    return f'{issuer}{WELL_KNOWN_OPENID_CONFIGURATION}'


def normalize_issuer(issuer: str) -> str:
    """Issuer for comparisons: lowercase scheme and host, no trailing slash."""
    raw = str(issuer or '').strip().rstrip('/')
    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        return raw
    return urlunparse(parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()))


def fetch_oidc_discovery(server_url: str) -> dict:
    url = discovery_url_for_server_url(server_url)
    if not url:
        return {}
    document = safe_get_json(url)
    return document if isinstance(document, dict) else {}


OIDC_DISCOVERY_ENDPOINT_KEYS = (
    'authorization_endpoint',
    'token_endpoint',
    'userinfo_endpoint',
    'jwks_uri',
)


def _require_https_public_url(value: object, *, key: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise OAuthProviderResponseError(f'OpenID Connect discovery is missing {key}.')
    parsed = urlparse(value.strip())
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise OAuthProviderResponseError(f'OpenID Connect discovery {key} must be an https URL.')
    try:
        assert_public_http_url(value.strip())
    except SSRFError as exc:
        raise OAuthProviderResponseError(f'OpenID Connect discovery {key} is not a public URL.') from exc


def validate_oidc_discovery_document(document: object, *, expected_issuer: str) -> dict:
    """Bind the document to ``expected_issuer`` and require public https endpoints."""
    if not isinstance(document, dict):
        raise OAuthProviderResponseError('OpenID Connect discovery document is not a JSON object.')
    issuer = document.get('issuer')
    if not isinstance(issuer, str) or not issuer.strip():
        raise OAuthProviderResponseError('OpenID Connect discovery is missing issuer.')
    if normalize_issuer(issuer) != normalize_issuer(expected_issuer):
        raise OAuthProviderResponseError(
            'OpenID Connect discovery issuer does not match the configured server_url.',
            code='oauth_discovery_issuer_mismatch',
        )
    if urlparse(issuer.strip()).scheme != 'https':
        raise OAuthProviderResponseError('OpenID Connect issuer must be an https URL.')
    for key in OIDC_DISCOVERY_ENDPOINT_KEYS:
        _require_https_public_url(document.get(key), key=key)
    return document


def load_validated_oidc_discovery(*, discovery_url: str, expected_issuer: str) -> dict:
    try:
        document = safe_get_json(discovery_url)
    except Exception as exc:
        raise OAuthProviderResponseError(
            'Could not load the OpenID Connect discovery document.',
            code='oauth_provider_unavailable',
        ) from exc
    return validate_oidc_discovery_document(document, expected_issuer=expected_issuer)
