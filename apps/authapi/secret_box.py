"""Encrypt small secrets stored in the database (Fernet, authenticated encryption).

The key comes from ``STAFF_TOTP_ENCRYPTION_KEY`` (a Fernet key) when set. Otherwise it is
derived with HKDF from ``SECRET_KEY``, so rotating ``SECRET_KEY`` without keeping the old one in
``SECRET_KEY_FALLBACKS`` makes stored secrets unreadable. Re-enroll those accounts then.
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings

PREFIX = 'enc1:'
_INFO = b'shellui-identity staff-totp secret v1'


class SecretBoxError(Exception):
    """The stored secret cannot be decrypted with the configured keys."""


def _derived(secret_key: str) -> Fernet:
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(secret_key.encode('utf-8'))
    return Fernet(base64.urlsafe_b64encode(raw))


def _keys() -> MultiFernet:
    explicit = str(getattr(settings, 'STAFF_TOTP_ENCRYPTION_KEY', '') or '').strip()
    if explicit:
        return MultiFernet([Fernet(explicit.encode('ascii'))])
    candidates = [settings.SECRET_KEY, *list(getattr(settings, 'SECRET_KEY_FALLBACKS', []) or [])]
    return MultiFernet([_derived(str(key)) for key in candidates])


def encrypt_text(plain: str) -> str:
    if not plain:
        return ''
    return PREFIX + _keys().encrypt(plain.encode('utf-8')).decode('ascii')


def decrypt_text(stored: str) -> str:
    if not stored:
        return ''
    if not stored.startswith(PREFIX):
        raise SecretBoxError('Stored secret is not encrypted.')
    try:
        return _keys().decrypt(stored[len(PREFIX):].encode('ascii')).decode('utf-8')
    except (InvalidToken, ValueError) as exc:
        raise SecretBoxError('Stored secret cannot be decrypted with the configured keys.') from exc
