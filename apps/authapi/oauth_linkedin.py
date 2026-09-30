"""Fixed LinkedIn OpenID Connect endpoints (not company-configurable)."""

from __future__ import annotations

from urllib.parse import urlparse

from allauth.socialaccount.providers.oauth2.client import OAuth2Error

LINKEDIN_OIDC_SERVER_URL = 'https://www.linkedin.com/oauth'
LINKEDIN_OIDC_DISCOVERY_URL = f'{LINKEDIN_OIDC_SERVER_URL}/.well-known/openid-configuration'
LINKEDIN_ISSUER = 'https://www.linkedin.com/oauth'

LINKEDIN_AUTHORIZE_HOST = 'www.linkedin.com'
LINKEDIN_TOKEN_HOST = 'www.linkedin.com'
LINKEDIN_USERINFO_HOST = 'api.linkedin.com'
LINKEDIN_JWKS_HOST = 'www.linkedin.com'


def assert_linkedin_oidc_discovery_hosts(document: dict) -> None:
    """Fail closed when LinkedIn discovery points OAuth traffic at unexpected hosts."""
    if not isinstance(document, dict):
        raise OAuth2Error('Invalid LinkedIn OpenID discovery document.')
    checks: tuple[tuple[str, frozenset[str]], ...] = (
        ('authorization_endpoint', frozenset({LINKEDIN_AUTHORIZE_HOST})),
        ('token_endpoint', frozenset({LINKEDIN_TOKEN_HOST})),
        ('userinfo_endpoint', frozenset({LINKEDIN_USERINFO_HOST})),
        ('jwks_uri', frozenset({LINKEDIN_JWKS_HOST})),
    )
    for key, allowed in checks:
        raw = document.get(key)
        if not isinstance(raw, str) or not raw.strip():
            raise OAuth2Error(f'LinkedIn discovery missing {key}.')
        host = (urlparse(raw.strip()).hostname or '').lower()
        if host not in allowed:
            raise OAuth2Error(
                f'LinkedIn discovery {key} host {host!r} is not allowed (expected one of {sorted(allowed)!r}).'
            )
