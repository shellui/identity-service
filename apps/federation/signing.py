"""Sign and verify federation JWTs with the deployment RSA key or a pinned JWKS."""

from __future__ import annotations

import json
import uuid
from typing import Any

import jwt
from django.conf import settings
from django.utils import timezone
from jwt.algorithms import RSAAlgorithm

CLOCK_SKEW = 60


class TokenError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def issuer() -> str:
    return (getattr(settings, 'JWT_ISSUER', None) or '').strip().rstrip('/')


def sign_rs256(claims: dict[str, Any]) -> str:
    key = getattr(settings, 'JWT_SIGNING_KEY', None)
    private_pem = getattr(key, 'private_pem', None)
    if not private_pem:
        raise TokenError('signing_key_unavailable')
    headers = {'kid': key.kid} if getattr(key, 'kid', '') else None
    token = jwt.encode(claims, private_pem, algorithm='RS256', headers=headers)
    if isinstance(token, bytes):
        return token.decode('utf-8')
    return token


def public_jwks() -> dict:
    key = getattr(settings, 'JWT_SIGNING_KEY', None)
    if key is None:
        return {'keys': []}
    from apps.authapi.jwks import build_jwks_document

    return build_jwks_document(key, getattr(settings, 'JWT_PREVIOUS_VERIFYING_KEYS', []))


def verify_pinned(
    token: str,
    *,
    audience: str,
    issuer_url: str,
    require: list[str] | None = None,
) -> dict[str, Any]:
    """Verify RS256 against GLOBAL_JWKS. No network fetch."""
    required = require or ['exp', 'iat', 'iss', 'aud']
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise TokenError('invalid_token') from exc
    if header.get('alg') != 'RS256':
        raise TokenError('invalid_token')
    kid = header.get('kid')
    if not isinstance(kid, str) or not kid:
        raise TokenError('invalid_token')
    jwk = _pinned_jwk(kid)
    if jwk is None:
        raise TokenError('invalid_token')
    try:
        public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            audience=audience,
            issuer=issuer_url.rstrip('/'),
            leeway=CLOCK_SKEW,
            options={'require': required},
        )
    except jwt.InvalidTokenError as exc:
        raise TokenError('invalid_token') from exc
    if not isinstance(claims, dict):
        raise TokenError('invalid_token')
    return claims


def new_jti() -> str:
    return uuid.uuid4().hex


def unix_now() -> int:
    return int(timezone.now().timestamp())


def _pinned_jwk(kid: str) -> dict | None:
    document = getattr(settings, 'GLOBAL_JWKS', None) or {}
    keys = document.get('keys') if isinstance(document, dict) else None
    if not isinstance(keys, list):
        return None
    for entry in keys:
        if isinstance(entry, dict) and entry.get('kid') == kid and entry.get('kty') == 'RSA':
            if entry.get('alg') not in {None, 'RS256'}:
                return None
            return entry
    return None
