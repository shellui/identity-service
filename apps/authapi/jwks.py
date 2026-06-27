"""JWT signing keys and JWKS document generation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from django.core.exceptions import ImproperlyConfigured

MIN_RSA_KEY_SIZE = 2048


@dataclass(frozen=True)
class JwtSigningKey:
    kid: str
    private_pem: str
    public_pem: str
    algorithm: str = 'RS256'


@dataclass(frozen=True)
class JwtVerifyingKey:
    kid: str
    public_pem: str
    algorithm: str = 'RS256'


def normalize_pem(value: str) -> str:
    """Accept PEM inline or with literal ``\\n`` sequences from env vars."""
    pem = value.strip()
    if not pem:
        return ''
    if '\\n' in pem:
        pem = pem.replace('\\n', '\n')
    return pem


def _int_to_base64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, 'big')).rstrip(b'=').decode('ascii')


def compute_rsa_kid(public_pem: str) -> str:
    """RFC 7638 JWK thumbprint used as ``kid``."""
    public_key = load_pem_public_key(public_pem.encode(), backend=default_backend())
    numbers = public_key.public_numbers()
    canonical = json.dumps(
        {
            'e': _int_to_base64url(numbers.e),
            'kty': 'RSA',
            'n': _int_to_base64url(numbers.n),
        },
        separators=(',', ':'),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


def _load_rsa_private_key(pem: str):
    key = load_pem_private_key(pem.encode(), password=None, backend=default_backend())
    if key.key_size < MIN_RSA_KEY_SIZE:
        raise ImproperlyConfigured(
            f'JWT RSA private key must be at least {MIN_RSA_KEY_SIZE} bits (got {key.key_size}).'
        )
    return key


def _load_rsa_public_key(pem: str):
    key = load_pem_public_key(pem.encode(), backend=default_backend())
    if key.key_size < MIN_RSA_KEY_SIZE:
        raise ImproperlyConfigured(
            f'JWT RSA public key must be at least {MIN_RSA_KEY_SIZE} bits (got {key.key_size}).'
        )
    return key


def public_pem_from_private(private_pem: str) -> str:
    private_key = _load_rsa_private_key(private_pem)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_bytes.decode()


def rsa_public_key_to_jwk(public_pem: str, kid: str) -> dict:
    public_key = _load_rsa_public_key(public_pem)
    numbers = public_key.public_numbers()
    return {
        'kty': 'RSA',
        'use': 'sig',
        'alg': 'RS256',
        'kid': kid,
        'n': _int_to_base64url(numbers.n),
        'e': _int_to_base64url(numbers.e),
    }


def generate_rsa_key_pair(key_size: int = 3072) -> tuple[str, str]:
    if key_size < MIN_RSA_KEY_SIZE:
        raise ValueError(f'RSA key size must be at least {MIN_RSA_KEY_SIZE} bits.')
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def load_signing_key(
    *,
    private_pem: str,
    public_pem: str = '',
    kid: str = '',
) -> JwtSigningKey:
    private_pem = normalize_pem(private_pem)
    if not private_pem:
        raise ImproperlyConfigured('JWT_PRIVATE_KEY is required for RS256 signing.')

    _load_rsa_private_key(private_pem)
    resolved_public = normalize_pem(public_pem) or public_pem_from_private(private_pem)
    _load_rsa_public_key(resolved_public)
    resolved_kid = kid.strip() or compute_rsa_kid(resolved_public)
    return JwtSigningKey(
        kid=resolved_kid,
        private_pem=private_pem,
        public_pem=resolved_public,
    )


def load_verifying_key(*, public_pem: str, kid: str = '') -> JwtVerifyingKey:
    public_pem = normalize_pem(public_pem)
    if not public_pem:
        raise ImproperlyConfigured('JWT public key PEM is empty.')
    _load_rsa_public_key(public_pem)
    resolved_kid = kid.strip() or compute_rsa_kid(public_pem)
    return JwtVerifyingKey(kid=resolved_kid, public_pem=public_pem)


def build_jwks_document(
    active_key: JwtSigningKey,
    previous_keys: list[JwtVerifyingKey] | None = None,
) -> dict:
    keys = [rsa_public_key_to_jwk(active_key.public_pem, active_key.kid)]
    seen_kids = {active_key.kid}
    for entry in previous_keys or []:
        if entry.kid in seen_kids:
            continue
        keys.append(rsa_public_key_to_jwk(entry.public_pem, entry.kid))
        seen_kids.add(entry.kid)
    return {'keys': keys}


def resolve_jwt_configuration(
    *,
    secret_key: str,
    debug: bool,
    private_key_pem: str = '',
    public_key_pem: str = '',
    key_id: str = '',
    previous_public_key_pem: str = '',
    previous_key_id: str = '',
    accept_hs256_legacy: bool | None = None,
) -> dict:
    """
    Return JWT runtime settings derived from environment variables.

    RS256 is used when ``JWT_PRIVATE_KEY`` is set. Otherwise HS256 with
    ``SECRET_KEY`` is kept for backward compatibility.
    """
    private_pem = normalize_pem(private_key_pem)
    previous_keys: list[JwtVerifyingKey] = []
    previous_pem = normalize_pem(previous_public_key_pem)
    if previous_pem:
        previous_keys.append(
            load_verifying_key(public_pem=previous_pem, kid=previous_key_id)
        )

    if private_pem:
        signing_key = load_signing_key(
            private_pem=private_pem,
            public_pem=public_key_pem,
            kid=key_id,
        )
        hs256_legacy = accept_hs256_legacy if accept_hs256_legacy is not None else True
        return {
            'algorithm': 'RS256',
            'signing_key': signing_key.private_pem,
            'verifying_key': signing_key.public_pem,
            'active_key_id': signing_key.kid,
            'signing_key_obj': signing_key,
            'previous_verifying_keys': previous_keys,
            'jwks_enabled': True,
            'accept_hs256_legacy': hs256_legacy,
            'requires_rs256': False,
        }

    if not debug:
        hs256_legacy = accept_hs256_legacy if accept_hs256_legacy is not None else True
        return {
            'algorithm': 'HS256',
            'signing_key': secret_key,
            'verifying_key': secret_key,
            'active_key_id': '',
            'signing_key_obj': None,
            'previous_verifying_keys': [],
            'jwks_enabled': False,
            'accept_hs256_legacy': hs256_legacy,
            'requires_rs256': True,
        }

    hs256_legacy = accept_hs256_legacy if accept_hs256_legacy is not None else True
    return {
        'algorithm': 'HS256',
        'signing_key': secret_key,
        'verifying_key': secret_key,
        'active_key_id': '',
        'signing_key_obj': None,
        'previous_verifying_keys': [],
        'jwks_enabled': False,
        'accept_hs256_legacy': hs256_legacy,
        'requires_rs256': False,
    }


def read_jwt_env() -> dict:
    """Read JWT-related environment variables."""
    raw_legacy = os.getenv('JWT_ACCEPT_HS256_LEGACY', '').strip().lower()
    if raw_legacy in {'1', 'true', 'yes', 'on'}:
        accept_hs256_legacy = True
    elif raw_legacy in {'0', 'false', 'no', 'off'}:
        accept_hs256_legacy = False
    else:
        accept_hs256_legacy = None

    return {
        'private_key_pem': os.getenv('JWT_PRIVATE_KEY', ''),
        'public_key_pem': os.getenv('JWT_PUBLIC_KEY', ''),
        'key_id': os.getenv('JWT_KEY_ID', ''),
        'previous_public_key_pem': os.getenv('JWT_PREVIOUS_PUBLIC_KEY', ''),
        'previous_key_id': os.getenv('JWT_PREVIOUS_KEY_ID', ''),
        'accept_hs256_legacy': accept_hs256_legacy,
    }
