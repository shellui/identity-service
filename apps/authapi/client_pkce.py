"""Client PKCE (RFC 7636, S256 only) for the Shellui session code.

The desktop app keeps the verifier. identity-service stores the S256 challenge
and checks the verifier when the app exchanges ``shellui_auth_code``. The
verifier is never stored, logged, or put on a webhook.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections.abc import Mapping

CHALLENGE_RE = re.compile(r'^[A-Za-z0-9\-_]{43,128}$')
VERIFIER_RE = re.compile(r'^[A-Za-z0-9\-._~]{43,128}$')

PKCE_REQUIRED = 'pkce_required'
INVALID_CODE_CHALLENGE = 'invalid_code_challenge'
INVALID_CODE_CHALLENGE_METHOD = 'invalid_code_challenge_method'
INVALID_CODE_VERIFIER = 'invalid_code_verifier'
PKCE_VERIFICATION_FAILED = 'pkce_verification_failed'


class PkceError(Exception):
    def __init__(self, message: str, error_code: str):
        super().__init__(message)
        self.message = message
        self.error_code = error_code


def s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')


def parse_client_pkce(code_challenge, code_challenge_method, *, required: bool) -> str:
    """Return the challenge to store, or '' when PKCE is absent and optional.

    Raises PkceError when the pair is incomplete, not S256, or required and missing.
    """
    challenge = str(code_challenge or '').strip()
    method = str(code_challenge_method or '').strip()
    if not challenge and not method:
        if required:
            raise PkceError(
                'code_challenge is required for this redirect.',
                PKCE_REQUIRED,
            )
        return ''
    if method != 'S256':
        raise PkceError(
            'code_challenge_method must be S256.',
            INVALID_CODE_CHALLENGE_METHOD,
        )
    if not CHALLENGE_RE.fullmatch(challenge):
        raise PkceError('Invalid code_challenge.', INVALID_CODE_CHALLENGE)
    return challenge


def verify_client_pkce(
    *,
    code_challenge: str | None,
    code_verifier: str | None,
    required: bool,
) -> tuple[str | None, str | None]:
    """Return ``(message, error_code)`` or ``(None, None)``.

    Does not return the verifier. A missing challenge is an error only when
    ``required`` is true (custom-scheme redirects).
    """
    stored = str(code_challenge or '').strip()
    verifier = str(code_verifier or '').strip()
    if not stored:
        if required:
            return 'code_verifier is required for this redirect.', PKCE_REQUIRED
        return None, None
    if not verifier:
        return 'code_verifier is required for this redirect.', PKCE_REQUIRED
    if not VERIFIER_RE.fullmatch(verifier):
        return 'Invalid code_verifier.', INVALID_CODE_VERIFIER
    expected = s256_challenge(verifier)
    if len(expected) != len(stored) or not hmac.compare_digest(expected, stored):
        return 'code_verifier does not match code_challenge.', PKCE_VERIFICATION_FAILED
    return None, None


def error_code_for_pkce_message(message: str | None) -> str | None:
    return {
        'code_challenge is required for this redirect.': PKCE_REQUIRED,
        'code_challenge_method must be S256.': INVALID_CODE_CHALLENGE_METHOD,
        'Invalid code_challenge.': INVALID_CODE_CHALLENGE,
        'code_verifier is required for this redirect.': PKCE_REQUIRED,
        'Invalid code_verifier.': INVALID_CODE_VERIFIER,
        'code_verifier does not match code_challenge.': PKCE_VERIFICATION_FAILED,
    }.get(message or '')


def presented_pkce_error(data: Mapping, *, required: bool) -> tuple[str, str] | None:
    """Validate a challenge and verifier sent together (legacy token endpoints).

    Legacy token endpoints (`/oauth/exchange`, provider login) still treat
    PKCE as optional for http(s). A custom-scheme redirect without S256 PKCE
    returns an error. When a challenge is present, the verifier must match it.
    Session-code sign-in requires S256 on every redirect. That check lives in
    the authorize, magic-link, and session-code paths, not here.
    """
    try:
        challenge = parse_client_pkce(
            data.get('code_challenge'),
            data.get('code_challenge_method'),
            required=required,
        )
    except PkceError as exc:
        return exc.message, exc.error_code
    if not challenge:
        return None
    message, error_code = verify_client_pkce(
        code_challenge=challenge,
        code_verifier=data.get('code_verifier'),
        required=True,
    )
    if message:
        return message, error_code or PKCE_VERIFICATION_FAILED
    return None
