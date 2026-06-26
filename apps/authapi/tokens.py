"""ShellUI JWT token classes with optional ``kid`` header for RS256."""

from __future__ import annotations

from typing import Any

import jwt
from django.conf import settings
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import AccessToken as BaseAccessToken
from rest_framework_simplejwt.tokens import RefreshToken as BaseRefreshToken


class ShellUITokenBackend(TokenBackend):
    """Adds ``kid`` to JWT headers when an active key id is configured."""

    def encode(self, payload: dict[str, Any]) -> str:
        jwt_payload = payload.copy()
        if self.audience is not None:
            jwt_payload['aud'] = self.audience
        if self.issuer is not None:
            jwt_payload['iss'] = self.issuer

        headers: dict[str, str] = {}
        kid = getattr(settings, 'JWT_ACTIVE_KEY_ID', '')
        if kid:
            headers['kid'] = kid

        token = jwt.encode(
            jwt_payload,
            self.prepared_signing_key,
            algorithm=self.algorithm,
            headers=headers or None,
            json_encoder=self.json_encoder,
        )
        if isinstance(token, bytes):
            return token.decode('utf-8')
        return token


def _shellui_token_backend() -> ShellUITokenBackend:
    return ShellUITokenBackend(
        api_settings.ALGORITHM,
        api_settings.SIGNING_KEY,
        api_settings.VERIFYING_KEY,
        api_settings.AUDIENCE,
        api_settings.ISSUER,
        api_settings.JWK_URL,
        api_settings.LEEWAY,
        api_settings.JSON_ENCODER,
    )


class ShellUIAccessToken(BaseAccessToken):
    @classmethod
    def get_token_backend(cls):
        return _shellui_token_backend()


class ShellUIRefreshToken(BaseRefreshToken):
    access_token_class = ShellUIAccessToken

    @classmethod
    def get_token_backend(cls):
        return _shellui_token_backend()
