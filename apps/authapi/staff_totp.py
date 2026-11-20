"""TOTP (RFC 6238) for Django staff sign-in. SHA-1, 6 digits, 30 second step."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def normalize_totp_code(raw: str | None) -> str:
    return ''.join(ch for ch in str(raw or '') if ch.isdigit())


def totp_at(secret: str, counter: int, *, digits: int = 6) -> str:
    padded = secret.strip().upper()
    padded += '=' * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def totp_matches(secret: str, code: str | None, *, now: int | None = None, window: int = 1, step: int = 30) -> bool:
    cleaned = normalize_totp_code(code)
    if len(cleaned) != 6 or not secret:
        return False
    moment = int(time.time()) if now is None else int(now)
    counter = moment // step
    for skew in range(-window, window + 1):
        if skew < 0 and counter + skew < 0:
            continue
        expected = totp_at(secret, counter + skew)
        if hmac.compare_digest(expected, cleaned):
            return True
    return False


def provisioning_uri(secret: str, username: str, *, issuer: str = 'Shellui') -> str:
    label = quote(f'{issuer}:{username}')
    return (
        f'otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}'
        '&algorithm=SHA1&digits=6&period=30'
    )
