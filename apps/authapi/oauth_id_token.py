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


MICROSOFT_JWKS_URL = 'https://login.microsoftonline.com/common/discovery/v2.0/keys'
GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs'
APPLE_JWKS_URL = 'https://appleid.apple.com/auth/keys'


def _verify_raw_id_token(
    *,
    entry: ProviderCatalogEntry,
    social_app: SocialApp,
    raw: str,
) -> dict:
    """Verify a JWT id_token with provider JWKS (allauth jwtkit)."""
    token = raw.strip()
    if not token:
        return {}
    try:
        if entry.docs_slug == 'microsoft' or entry.allauth_id == 'microsoft':
            tenant = str((social_app.settings or {}).get('tenant') or 'common').strip()
            issuer = f'https://login.microsoftonline.com/{tenant}/v2.0'
            return jwtkit.verify_and_decode(
                credential=token,
                keys_url=MICROSOFT_JWKS_URL,
                issuer=issuer,
                audience=[social_app.client_id],
                lookup_kid=jwtkit.lookup_kid_jwk,
            )
        if entry.docs_slug == 'google' or entry.allauth_id == 'google':
            return jwtkit.verify_and_decode(
                credential=token,
                keys_url=GOOGLE_JWKS_URL,
                issuer='https://accounts.google.com',
                audience=[social_app.client_id],
                lookup_kid=jwtkit.lookup_kid_jwk,
            )
        if entry.allauth_id == 'openid_connect':
            settings_data = social_app.settings if isinstance(social_app.settings, dict) else {}
            issuer = str(settings_data.get('server_url') or '').strip().rstrip('/')
            if not issuer:
                return {}
            jwks_url = f'{issuer}/jwks' if not issuer.endswith('jwks') else issuer
            if 'openid-configuration' in issuer or issuer.endswith('/'):
                jwks_url = f'{issuer.rstrip("/")}/jwks'
            return jwtkit.verify_and_decode(
                credential=token,
                keys_url=jwks_url,
                issuer=issuer,
                audience=[social_app.client_id],
                lookup_kid=jwtkit.lookup_kid_jwk,
            )
    except OAuth2Error:
        return {}
    except Exception:
        return {}
    return {}


def verified_login_id_token_claims(
    *,
    entry: ProviderCatalogEntry | None,
    social_app: SocialApp,
    id_token_raw: str | None,
    userinfo: dict,
) -> dict:
    """Claims safe for account linking (JWKS-verified or allauth-verified dict)."""
    info = userinfo if isinstance(userinfo, dict) else {}
    verified = info.get('_verified_id_token_claims')
    if isinstance(verified, dict) and verified:
        return dict(verified)
    if entry is None:
        return {}
    raw = (id_token_raw or '').strip()
    if not raw:
        return {}
    return _verify_raw_id_token(entry=entry, social_app=social_app, raw=raw)


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
