"""Fixed LinkedIn OpenID Connect endpoints (not company-configurable)."""

from __future__ import annotations

LINKEDIN_OIDC_SERVER_URL = 'https://www.linkedin.com/oauth'
LINKEDIN_OIDC_DISCOVERY_URL = f'{LINKEDIN_OIDC_SERVER_URL}/.well-known/openid-configuration'
LINKEDIN_ISSUER = 'https://www.linkedin.com/oauth'

LINKEDIN_AUTHORIZE_HOST = 'www.linkedin.com'
LINKEDIN_TOKEN_HOST = 'www.linkedin.com'
LINKEDIN_USERINFO_HOST = 'api.linkedin.com'
LINKEDIN_JWKS_HOST = 'www.linkedin.com'
