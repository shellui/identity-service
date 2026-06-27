"""JWT auth extended to validate personal access tokens (``pat_id`` claim + DB row)."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.utils import timezone
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.exceptions import InvalidToken, TokenBackendError
from rest_framework_simplejwt.settings import api_settings

from .models import PersonalAccessToken


class ShellUIJWTAuthentication(JWTAuthentication):
    """Same as SimpleJWT, but rejects revoked PATs and mismatched ``jti`` / user."""

    def get_validated_token(self, raw_token):
        validated = self._decode_with_configured_keys(raw_token)
        pat_id = validated.get('pat_id')
        if pat_id is None:
            return validated

        try:
            pat_uuid = uuid.UUID(str(pat_id))
        except (TypeError, ValueError) as exc:
            raise InvalidToken({'detail': 'Invalid personal access token id.'}) from exc

        try:
            pat = PersonalAccessToken.objects.select_related('user').get(pk=pat_uuid)
        except PersonalAccessToken.DoesNotExist as exc:
            raise InvalidToken({'detail': 'Personal access token not found.'}) from exc

        if pat.revoked_at is not None:
            raise InvalidToken({'detail': 'Personal access token revoked.'})

        claim_jti = validated.get('jti')
        if claim_jti is None or str(pat.jti) != str(claim_jti):
            raise InvalidToken({'detail': 'Personal access token mismatch.'})

        uid = validated.get(api_settings.USER_ID_CLAIM)
        if uid is None or int(pat.user_id) != int(uid):
            raise InvalidToken({'detail': 'Personal access token user mismatch.'})

        claim_ro = validated.get('pat_ro')
        if claim_ro is not None and bool(pat.read_only) != bool(claim_ro):
            raise InvalidToken({'detail': 'Personal access token scope mismatch.'})

        claim_agm = validated.get('pat_agm')
        if claim_agm is not None and bool(pat.access_global_metrics) != bool(claim_agm):
            raise InvalidToken({'detail': 'Personal access token scope mismatch.'})

        PersonalAccessToken.objects.filter(pk=pat.pk).update(last_used_at=timezone.now())
        return validated

    def _decode_with_configured_keys(self, raw_token):
        decode_errors: list[Exception] = []
        try:
            return super().get_validated_token(raw_token)
        except InvalidToken as exc:
            decode_errors.append(exc)

        for previous_key in getattr(settings, 'JWT_PREVIOUS_VERIFYING_KEYS', []):
            backend = TokenBackend(
                algorithm='RS256',
                verifying_key=previous_key.public_pem,
            )
            try:
                return backend.decode(raw_token)
            except TokenBackendError as exc:
                decode_errors.append(exc)

        if (
            getattr(settings, 'JWT_ACCEPT_HS256_LEGACY', False)
            and getattr(settings, 'JWT_ALGORITHM', 'HS256') != 'HS256'
        ):
            legacy_backend = TokenBackend(
                algorithm='HS256',
                signing_key=settings.SECRET_KEY,
                verifying_key=settings.SECRET_KEY,
            )
            try:
                return legacy_backend.decode(raw_token)
            except TokenBackendError as exc:
                decode_errors.append(exc)

        if decode_errors:
            raise InvalidToken({'detail': 'Token is invalid or expired.'}) from decode_errors[0]
        raise InvalidToken({'detail': 'Token is invalid or expired.'})
