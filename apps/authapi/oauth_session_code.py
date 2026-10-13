"""One-time OAuth session delivery codes (H-03 alternative to URL fragment tokens)."""

from __future__ import annotations

import secrets
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from apps.authapi.client_pkce import verify_client_pkce
from apps.companies.redirect_allowlist import canonical_url_no_fragment, is_custom_scheme_redirect, origin_of_url

from .models import OAuthSessionDeliveryCode

OAUTH_SESSION_CODE_PARAM = 'shellui_auth_code'
OAUTH_SESSION_CODE_TTL_SECONDS = 120


def oauth_session_code_ttl() -> timedelta:
    raw = getattr(settings, 'OAUTH_SESSION_CODE_TTL_SECONDS', OAUTH_SESSION_CODE_TTL_SECONDS)
    return timedelta(seconds=max(30, int(raw)))


def create_oauth_session_delivery_code(
    *,
    user,
    company,
    redirect_to: str,
    token_payload: dict,
    code_challenge: str = '',
) -> OAuthSessionDeliveryCode:
    code = secrets.token_urlsafe(32)
    expires_at = timezone.now() + oauth_session_code_ttl()
    return OAuthSessionDeliveryCode.objects.create(
        code=code,
        user=user,
        company=company,
        redirect_to=canonical_url_no_fragment(redirect_to),
        code_challenge=(code_challenge or '')[:128],
        token_payload=token_payload,
        expires_at=expires_at,
    )


def build_code_redirect_url(redirect_to: str, code: str) -> str:
    base = canonical_url_no_fragment(redirect_to)
    separator = '&' if '?' in base else '?'
    return f'{base}{separator}{OAUTH_SESSION_CODE_PARAM}={code}'


def redeem_oauth_session_code(
    *,
    code: str,
    redirect_to: str,
    request_origin: str | None = None,
    code_verifier: str | None = None,
) -> tuple[dict | None, str | None]:
    raw_code = (code or '').strip()
    if not raw_code:
        return None, 'Missing auth code.'

    try:
        row = OAuthSessionDeliveryCode.objects.select_related('user', 'company').get(code=raw_code)
    except OAuthSessionDeliveryCode.DoesNotExist:
        return None, 'Invalid auth code.'

    if row.redeemed_at is not None:
        return None, 'Auth code already used.'

    if row.expires_at <= timezone.now():
        return None, 'Auth code expired.'

    requested = canonical_url_no_fragment(redirect_to)
    if requested != row.redirect_to:
        return None, 'redirect_to does not match auth code.'

    custom_scheme = is_custom_scheme_redirect(row.redirect_to)
    pkce_message, _pkce_code = verify_client_pkce(
        code_challenge=row.code_challenge,
        code_verifier=code_verifier,
        required=custom_scheme,
    )
    if pkce_message:
        # Leave the code unredeemed so the app can retry with the verifier.
        # A wrong verifier is not brute-forced: the verifier is 43-128 characters.
        return None, pkce_message

    # A desktop app has no browser origin that matches the custom scheme
    # (Tauri sends tauri://localhost, or no Origin). Skip the Origin check
    # only after PKCE has succeeded for that custom-scheme redirect.
    # http(s) redirects keep the Origin check, including when PKCE was optional.
    if not custom_scheme and request_origin:
        allowed_origin = origin_of_url(row.redirect_to)
        if allowed_origin and request_origin.rstrip('/') != allowed_origin.rstrip('/'):
            return None, 'Origin does not match redirect_to.'

    row.redeemed_at = timezone.now()
    row.save(update_fields=['redeemed_at'])
    payload = row.token_payload
    if not isinstance(payload, dict):
        return None, 'Invalid auth code payload.'
    return payload, None
