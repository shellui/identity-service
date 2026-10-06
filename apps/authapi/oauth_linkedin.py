"""Fixed LinkedIn OpenID Connect endpoints (not company-configurable)."""

from __future__ import annotations

from urllib.parse import urlparse

from apps.authapi.oauth_errors import OAuthProviderResponseError
from apps.authapi.oauth_oidc_discovery import validate_oidc_discovery_document
from apps.authapi.oauth_safe_http import safe_get_json

LINKEDIN_OIDC_SERVER_URL = 'https://www.linkedin.com/oauth'
LINKEDIN_OIDC_DISCOVERY_URL = f'{LINKEDIN_OIDC_SERVER_URL}/.well-known/openid-configuration'
LINKEDIN_ISSUER = 'https://www.linkedin.com/oauth'

LINKEDIN_AUTHORIZE_HOST = 'www.linkedin.com'
LINKEDIN_TOKEN_HOST = 'www.linkedin.com'
LINKEDIN_USERINFO_HOST = 'api.linkedin.com'
LINKEDIN_JWKS_HOST = 'www.linkedin.com'

LINKEDIN_ENDPOINT_HOSTS: tuple[tuple[str, str], ...] = (
    ('authorization_endpoint', LINKEDIN_AUTHORIZE_HOST),
    ('token_endpoint', LINKEDIN_TOKEN_HOST),
    ('userinfo_endpoint', LINKEDIN_USERINFO_HOST),
    ('jwks_uri', LINKEDIN_JWKS_HOST),
)


def assert_linkedin_oidc_discovery_hosts(document: object) -> None:
    """Fail closed when LinkedIn discovery points OAuth traffic at unexpected hosts."""
    if not isinstance(document, dict):
        raise OAuthProviderResponseError('Invalid LinkedIn OpenID discovery document.')
    for key, allowed_host in LINKEDIN_ENDPOINT_HOSTS:
        raw = document.get(key)
        if not isinstance(raw, str) or not raw.strip():
            raise OAuthProviderResponseError(f'LinkedIn discovery is missing {key}.')
        parsed = urlparse(raw.strip())
        host = (parsed.hostname or '').lower()
        if parsed.scheme != 'https' or host != allowed_host or parsed.port not in (None, 443):
            raise OAuthProviderResponseError(
                f'LinkedIn discovery {key} host {host!r} is not allowed (expected {allowed_host!r}).',
                code='oauth_provider_host_not_allowed',
            )


def load_linkedin_oidc_discovery() -> dict:
    """Fetch the pinned LinkedIn discovery document and bind it to LinkedIn hosts and issuer."""
    try:
        document = safe_get_json(LINKEDIN_OIDC_DISCOVERY_URL)
    except Exception as exc:
        raise OAuthProviderResponseError(
            'Could not load the LinkedIn OpenID Connect discovery document.',
            code='oauth_provider_unavailable',
        ) from exc
    assert_linkedin_oidc_discovery_hosts(document)
    return validate_oidc_discovery_document(document, expected_issuer=LINKEDIN_ISSUER)
