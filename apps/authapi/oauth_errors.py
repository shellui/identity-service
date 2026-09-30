"""OAuth failures that carry a stable Shellui ``error_code`` for API and bounce responses."""

from __future__ import annotations

from allauth.socialaccount.providers.oauth2.client import OAuth2Error


class ShelluiOAuthError(OAuth2Error):
    default_code = 'oauth_signin_failed'
    default_status = 400

    def __init__(self, message: str, *, code: str | None = None, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.status_code = status_code or self.default_status


class OAuthIdTokenError(ShelluiOAuthError):
    """The token response id_token is missing, malformed, or fails Shellui verification."""

    default_code = 'oauth_id_token_invalid'


class OAuthSubjectMismatchError(ShelluiOAuthError):
    """Userinfo ``sub`` differs from the verified id_token ``sub`` (OIDC Core 5.3.2)."""

    default_code = 'oauth_subject_mismatch'


class OAuthProviderConfigError(ShelluiOAuthError):
    """Company OAuth settings are missing or invalid for this provider."""

    default_code = 'provider_oauth_misconfigured'
    default_status = 500


class OAuthProviderResponseError(ShelluiOAuthError):
    """The identity provider published endpoints or metadata Shellui refuses to trust."""

    default_code = 'oauth_discovery_invalid'
    default_status = 502
