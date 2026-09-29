"""Verified id_token claim extraction for OAuth account linking."""

from __future__ import annotations

import re
import time

import jwt
from allauth.socialaccount.internal import jwtkit
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.apple.views import AppleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Error

from apps.authapi.oauth_oidc_discovery import fetch_oidc_discovery
from apps.authapi.oauth_request_context import oauth_allauth_request
from apps.authapi.provider_registry import ProviderCatalogEntry

_MICROSOFT_ISSUER_RE = re.compile(
    r'^https://login\.microsoftonline\.com/[^/]+/v2\.0/?$',
    re.IGNORECASE,
)
_TENANT_GUID_RE = re.compile(
    r'^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$',
    re.IGNORECASE,
)

MICROSOFT_JWKS_URL = 'https://login.microsoftonline.com/common/discovery/v2.0/keys'
GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs'
APPLE_JWKS_URL = 'https://appleid.apple.com/auth/keys'

_MICROSOFT_DOMAIN_TID_CACHE_TTL_SECONDS = 3600
_microsoft_domain_tid_cache: dict[str, tuple[str | None, float]] = {}


def _read_microsoft_domain_tid_cache(key: str) -> str | None | object:
    cached = _microsoft_domain_tid_cache.get(key)
    if not cached:
        return _CACHE_MISS
    guid, expires_at = cached
    if expires_at <= time.monotonic():
        _microsoft_domain_tid_cache.pop(key, None)
        return _CACHE_MISS
    return guid


_CACHE_MISS = object()


def microsoft_tenant_guid_for_domain(tenant: str) -> str | None:
    """Resolve a Microsoft domain tenant name to its directory GUID via OIDC discovery."""
    key = (tenant or '').strip().lower()
    if not key or _TENANT_GUID_RE.match(key):
        return key if _TENANT_GUID_RE.match(key or '') else None
    cached = _read_microsoft_domain_tid_cache(key)
    if cached is not _CACHE_MISS:
        return cached  # type: ignore[return-value]
    discovery_url = f'https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration'
    guid: str | None = None
    try:
        discovery = fetch_oidc_discovery(discovery_url)
        issuer = str(discovery.get('issuer') or '').strip().rstrip('/')
        if issuer:
            tail = issuer.rsplit('/', 2)
            if len(tail) >= 2 and tail[-1] == 'v2.0':
                candidate = tail[-2]
                if _TENANT_GUID_RE.match(candidate):
                    guid = candidate
    except Exception:
        guid = None
    _microsoft_domain_tid_cache[key] = (
        guid,
        time.monotonic() + _MICROSOFT_DOMAIN_TID_CACHE_TTL_SECONDS,
    )
    return guid


def _issuer_from_unverified_jwt(raw: str) -> str:
    try:
        claims = jwt.decode(
            raw,
            options={'verify_signature': False},
            algorithms=['RS256', 'HS256', 'RS384', 'RS512', 'ES256'],
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


def _microsoft_issuer_from_token(raw: str) -> str:
    issuer = _issuer_from_unverified_jwt(raw)
    if not issuer:
        raise OAuth2Error('Invalid Microsoft id_token issuer.')
    issuer_norm = issuer.rstrip('/')
    if not issuer_norm.endswith('/v2.0'):
        issuer_norm = f'{issuer_norm}/v2.0'
    if not _MICROSOFT_ISSUER_RE.match(issuer_norm):
        raise OAuth2Error('Invalid Microsoft id_token issuer.')
    return issuer_norm


def _verify_microsoft_id_token(*, social_app: SocialApp, raw: str) -> dict:
    issuer_norm = _microsoft_issuer_from_token(raw)
    return jwtkit.verify_and_decode(
        credential=raw,
        keys_url=MICROSOFT_JWKS_URL,
        issuer=issuer_norm,
        audience=[social_app.client_id],
        lookup_kid=jwtkit.lookup_kid_jwk,
    )


def _verify_openid_connect_id_token(*, social_app: SocialApp, raw: str) -> dict:
    settings_data = social_app.settings if isinstance(getattr(social_app, 'settings', None), dict) else {}
    server_url = str(settings_data.get('server_url') or '').strip()
    if not server_url:
        raise OAuth2Error('Missing OpenID Connect server_url.')
    discovery = fetch_oidc_discovery(server_url)
    issuer = str(discovery.get('issuer') or '').strip().rstrip('/')
    jwks_uri = str(discovery.get('jwks_uri') or '').strip()
    if not issuer or not jwks_uri:
        raise OAuth2Error('Invalid OpenID Connect discovery document.')
    return jwtkit.verify_and_decode(
        credential=raw,
        keys_url=jwks_uri,
        issuer=issuer,
        audience=[social_app.client_id],
        lookup_kid=jwtkit.lookup_kid_jwk,
    )


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
    if entry.docs_slug == 'microsoft' or entry.allauth_id == 'microsoft':
        return _verify_microsoft_id_token(social_app=social_app, raw=token)
    if entry.docs_slug == 'google' or entry.allauth_id == 'google':
        return jwtkit.verify_and_decode(
            credential=token,
            keys_url=GOOGLE_JWKS_URL,
            issuer='https://accounts.google.com',
            audience=[social_app.client_id],
            lookup_kid=jwtkit.lookup_kid_jwk,
        )
    if entry.allauth_id == 'openid_connect':
        return _verify_openid_connect_id_token(social_app=social_app, raw=token)
    return {}


def verified_login_id_token_claims(
    *,
    entry: ProviderCatalogEntry | None,
    social_app: SocialApp,
    id_token_raw: str | None,
    userinfo: dict,
) -> dict:
    """Claims safe for account linking (JWKS-verified only)."""
    if entry is None:
        return {}
    raw = (id_token_raw or '').strip()
    if not raw:
        return {}
    try:
        verified = _verify_raw_id_token(entry=entry, social_app=social_app, raw=raw)
    except OAuth2Error:
        return {}
    except Exception:
        return {}
    return verified if isinstance(verified, dict) else {}


def microsoft_configured_tenant_is_guid(social_app: SocialApp) -> bool:
    settings_data = social_app.settings if isinstance(getattr(social_app, 'settings', None), dict) else {}
    tenant = str(settings_data.get('tenant') or '').strip()
    return bool(tenant and _TENANT_GUID_RE.match(tenant))
