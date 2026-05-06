"""JWT auth extended to validate personal access tokens (``pat_id`` claim + DB row)."""

from __future__ import annotations

import uuid

from django.utils import timezone
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.settings import api_settings

from .models import PersonalAccessToken


class ShellUIJWTAuthentication(JWTAuthentication):
    """Same as SimpleJWT, but rejects revoked PATs and mismatched ``jti`` / user."""

    def get_validated_token(self, raw_token):
        validated = super().get_validated_token(raw_token)
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
