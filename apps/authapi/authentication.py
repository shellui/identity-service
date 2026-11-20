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


def _verifying_key():
    """HS* verifies with the shared secret; RS*/ES* must verify with the public key."""
    if api_settings.ALGORITHM.startswith('HS'):
        return api_settings.SIGNING_KEY
    return api_settings.VERIFYING_KEY


def _is_mcp_endpoint(request) -> bool:
    path = getattr(request, 'path', '') or ''
    return path.rstrip('/') == '/mcp'


def _is_agent_token(validated) -> bool:
    if validated is None or not hasattr(validated, 'get'):
        return False
    if validated.get('agent_id') is not None:
        return True
    return str(validated.get('sub') or '').startswith('agent:')


def _reject_revoked_agent_refresh(validated) -> None:
    """A revoked or unknown agent refresh session is not a bearer."""
    from apps.agents.models import AgentRefreshSession

    jti = str(validated.get('jti') or '').strip()
    if not jti:
        raise InvalidToken({'detail': 'Refresh token revoked or unknown.'})
    try:
        agent_uuid = uuid.UUID(str(validated.get('agent_id')))
    except (TypeError, ValueError) as exc:
        raise InvalidToken({'detail': 'Refresh token revoked or unknown.'}) from exc
    try:
        session = AgentRefreshSession.objects.get(jti=jti, agent_id=agent_uuid)
    except AgentRefreshSession.DoesNotExist as exc:
        raise InvalidToken({'detail': 'Refresh token revoked or unknown.'}) from exc
    if session.revoked_at is not None or session.expires_at <= timezone.now():
        raise InvalidToken({'detail': 'Refresh token revoked.'})


def _reject_revoked_user_refresh(validated) -> None:
    """A revoked or unknown user refresh session is not a bearer."""
    from .models import RefreshTokenSession

    jti = str(validated.get('jti') or '').strip()
    if not jti:
        raise InvalidToken({'detail': 'Refresh token revoked or unknown.'})
    try:
        session = RefreshTokenSession.objects.get(jti=jti)
    except RefreshTokenSession.DoesNotExist as exc:
        raise InvalidToken({'detail': 'Refresh token revoked or unknown.'}) from exc
    if session.revoked_at is not None or session.expires_at <= timezone.now():
        raise InvalidToken({'detail': 'Refresh token revoked.'})


class ShellUIJWTAuthentication(JWTAuthentication):
    """Same as SimpleJWT, but rejects revoked PATs and mismatched ``jti`` / user."""

    def get_validated_token(self, raw_token):
        validated = self._decode_with_configured_keys(raw_token)
        if is_access_jti_denied(validated.get('jti')):
            raise InvalidToken({'detail': 'Access token revoked.'})
        if _is_agent_token(validated):
            return self._validate_agent_access_token(validated)
        self._require_identity_access_token(validated)
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

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None
        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None
        validated_token = self.get_validated_token(raw_token)
        if _is_agent_token(validated_token) and not _is_mcp_endpoint(request):
            raise InvalidToken({'detail': 'Agent tokens are only accepted on the MCP endpoint.'})
        return self.get_user(validated_token), validated_token

    def _validate_agent_access_token(self, validated):
        from apps.agents.models import Agent

        token_type = str(validated.get('token_type') or '')
        if token_type != 'access':
            if token_type == 'refresh':
                _reject_revoked_agent_refresh(validated)
            raise InvalidToken({'detail': 'Bearer authentication requires an access token.'})
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
        if _is_agent_token(validated_token):
            from apps.agents.models import Agent

            agent = Agent.objects.select_related('created_by').get(pk=validated_token['agent_id'])
            user = agent.created_by
            if user is None or not user.is_active:
                raise InvalidToken({'detail': 'Agent user unavailable.'})
            # Company role stays the user's membership. This does not grant owner.
            claim_owner = validated_token.get('owner_user_id')
            if claim_owner is not None and int(claim_owner) != int(user.pk):
                raise InvalidToken({'detail': 'Agent user mismatch.'})
            return user
        return super().get_user(validated_token)

    def _require_identity_access_token(self, validated):
        """Bearer calls outside an agent token need an access token for JWT_AUDIENCE."""
        token_type = str(validated.get('token_type') or '')
        if token_type == 'refresh':
            _reject_revoked_user_refresh(validated)
            raise InvalidToken({'detail': 'Bearer authentication requires an access token.'})
        if token_type != 'access':
            raise InvalidToken({'detail': 'Bearer authentication requires an access token.'})
        # ``api_settings.AUDIENCE`` is the identity audience baked into access tokens.
        # Tests often override ``JWT_AUDIENCE`` without reissuing that claim.
        expected = getattr(api_settings, 'AUDIENCE', None)
        if not expected:
            return
        aud = validated.get('aud')
        if isinstance(aud, str):
            matches = aud == expected
        elif isinstance(aud, (list, tuple)):
            matches = expected in aud
        else:
            matches = False
        if not matches:
            raise InvalidToken({'detail': 'Token audience is not the identity audience.'})

    def _decode_agent_jwt(self, raw_token: str) -> dict | None:
        import jwt

        issuer = api_settings.ISSUER or getattr(settings, 'JWT_ISSUER', None)
        try:
            payload = jwt.decode(
                raw_token,
                _verifying_key(),
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
