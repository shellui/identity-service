"""Verified id_token claim extraction for OAuth account linking."""

from __future__ import annotations

import jwt
from allauth.socialaccount.internal import jwtkit
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.apple.views import AppleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Error

from apps.authapi.oauth_request_context import oauth_allauth_request
from apps.authapi.provider_registry import ProviderCatalogEntry


def _issuer_from_unverified_jwt(raw: str) -> str:
    try:
        claims = jwt.decode(
            raw,
            options={'verify_signature': False},
            algorithms=['RS256', 'HS256', 'RS384', 'RS512'],
        )
    except Exception:
        return ''
    if isinstance(claims, dict):
        iss = claims.get('iss')
        if isinstance(iss, str):
            return iss.strip().rstrip('/')
    return ''


def issuer_from_social_account_extra(extra: dict) -> str:
    if not isinstance(extra, dict):
        return ''
    if isinstance(extra.get('iss'), str) and extra['iss'].strip():
        return extra['iss'].strip().rstrip('/')
    id_token = extra.get('id_token')
    if isinstance(id_token, dict):
        iss = id_token.get('iss')
        if isinstance(iss, str) and iss.strip():
            return iss.strip().rstrip('/')
    if isinstance(id_token, str) and id_token.strip():
        return _issuer_from_unverified_jwt(id_token.strip())
    userinfo = extra.get('userinfo')
    if isinstance(userinfo, dict):
        iss = userinfo.get('iss')
        if isinstance(iss, str) and iss.strip():
            return iss.strip().rstrip('/')
    return ''


def verify_apple_id_token_for_bridge(
    request,
    *,
    social_app: SocialApp,
    id_token: str,
    expected_nonce: str,
) -> dict:
    """Verify Apple form_post id_token (signature, iss, aud, nonce) before bridging to GET."""
    raw = (id_token or '').strip()
    if not raw:
        raise OAuth2Error('Missing Apple id_token.')
    nonce = (expected_nonce or '').strip()
    if not nonce:
        raise OAuth2Error('Missing OAuth nonce for Apple id_token verification.')
    with oauth_allauth_request(request, social_app=social_app):
        provider = AppleOAuth2Adapter(request).get_provider()
        claims = AppleOAuth2Adapter.get_verified_identity_data(provider, raw)
    token_nonce = str(claims.get('nonce') or '').strip()
    if not token_nonce or token_nonce != nonce:
        raise OAuth2Error('Apple id_token nonce does not match this authorize session.')
    return claims


def verified_id_token_claims_from_sociallogin(
    *,
    entry: ProviderCatalogEntry | None,
    sociallogin,
    token_response: dict | None = None,
) -> dict:
    """
    Return verified JWT claims for email-link policy decisions.

    Prefer allauth-verified id_token material already on the SocialLogin / token response.
    """
    response = token_response if isinstance(token_response, dict) else {}
    raw_id = response.get('id_token')
    if isinstance(raw_id, str) and raw_id.strip():
        if entry is not None and entry.docs_slug == 'apple':
            return {}
        if entry is not None and entry.allauth_id == 'openid_connect':
            return {}
    extra = sociallogin.account.extra_data if isinstance(sociallogin.account.extra_data, dict) else {}
    nested = extra.get('id_token')
    if isinstance(nested, dict):
        return dict(nested)
    state_id = sociallogin.state.get('id_token') if isinstance(getattr(sociallogin, 'state', None), dict) else None
    if isinstance(state_id, dict):
        return dict(state_id)
    return {}
