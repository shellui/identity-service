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
from .refresh_sessions import is_access_jti_denied


class ShellUIJWTAuthentication(JWTAuthentication):
    """Same as SimpleJWT, but rejects revoked PATs and mismatched ``jti`` / user."""

    def get_validated_token(self, raw_token):
        validated = self._decode_with_configured_keys(raw_token)
        if is_access_jti_denied(validated.get('jti')):
            raise InvalidToken({'detail': 'Access token revoked.'})
        agent_id = validated.get('agent_id')
        if agent_id is not None:
            return self._validate_agent_access_token(validated)
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

    def _validate_agent_access_token(self, validated):
        from apps.agents.models import Agent

        try:
            agent_uuid = uuid.UUID(str(validated.get('agent_id')))
        except (TypeError, ValueError) as exc:
            raise InvalidToken({'detail': 'Invalid agent id.'}) from exc
        try:
            agent = Agent.objects.select_related('created_by').get(pk=agent_uuid)
        except Agent.DoesNotExist as exc:
            raise InvalidToken({'detail': 'Agent not found.'}) from exc
        if not agent.is_active:
            raise InvalidToken({'detail': 'Agent is paused, revoked, or expired.'})
        token_company = validated.get('company_id')
        if token_company is None or int(agent.company_id) != int(token_company):
            raise InvalidToken({'detail': 'Agent company mismatch.'})
        return validated

    def get_user(self, validated_token):
        if validated_token.get('agent_id'):
            from apps.agents.models import Agent

            agent = Agent.objects.select_related('created_by').get(pk=validated_token['agent_id'])
            user = agent.created_by
            if user is None or not user.is_active:
                raise InvalidToken({'detail': 'Agent owner unavailable.'})
            return user
        return super().get_user(validated_token)

    def _decode_agent_jwt(self, raw_token: str) -> dict | None:
        import jwt

        issuer = getattr(settings, 'JWT_ISSUER', None)
        try:
            payload = jwt.decode(
                raw_token,
                api_settings.SIGNING_KEY,
                algorithms=[api_settings.ALGORITHM],
                issuer=issuer or None,
                options={'require': ['exp', 'sub', 'agent_id', 'aud'], 'verify_aud': False},
            )
        except jwt.PyJWTError:
            return None
        if not str(payload.get('sub', '')).startswith('agent:'):
            return None
        return payload

    def _decode_with_configured_keys(self, raw_token):
        agent_payload = self._decode_agent_jwt(raw_token)
        if agent_payload is not None:
            return agent_payload
        decode_errors: list[Exception] = []
        try:
            return super().get_validated_token(raw_token)
        except InvalidToken as exc:
            decode_errors.append(exc)

        issuer = getattr(settings, 'JWT_ISSUER', None)
        audience = getattr(settings, 'JWT_AUDIENCE', None)

        for previous_key in getattr(settings, 'JWT_PREVIOUS_VERIFYING_KEYS', []):
            backend = TokenBackend(
                algorithm='RS256',
                verifying_key=previous_key.public_pem,
                audience=audience,
                issuer=issuer,
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
                audience=audience,
                issuer=issuer,
            )
            try:
                return legacy_backend.decode(raw_token)
            except TokenBackendError as exc:
                decode_errors.append(exc)

        if decode_errors:
            raise InvalidToken({'detail': 'Token is invalid or expired.'}) from decode_errors[0]
        raise InvalidToken({'detail': 'Token is invalid or expired.'})
