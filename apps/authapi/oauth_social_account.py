"""SocialAccount storage keys and request-scoped SocialApp selection for OAuth."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp

from apps.authapi.provider_registry import ProviderCatalogEntry, resolve_catalog_slug

REQUEST_SOCIAL_APP_ATTR = 'shellui_oauth_social_app'


def bind_oauth_social_app(request, social_app: SocialApp) -> None:
    setattr(request, REQUEST_SOCIAL_APP_ATTR, social_app)


def get_bound_oauth_social_app(request) -> SocialApp | None:
    app = getattr(request, REQUEST_SOCIAL_APP_ATTR, None)
    return app if isinstance(app, SocialApp) else None


def social_account_provider_key(*, entry: ProviderCatalogEntry | None, social_app: SocialApp) -> str:
    if entry is not None and entry.allauth_id == 'openid_connect':
        sub = str(getattr(social_app, 'provider_id', '') or entry.social_app_provider_id()).strip()
        return sub or entry.docs_slug
    if entry is not None:
        return entry.allauth_id
    return str(social_app.provider).strip().lower()


def compose_social_account_uid(
    *,
    entry: ProviderCatalogEntry | None,
    social_app: SocialApp,
    raw_uid: str,
    id_token_claims: dict | None = None,
) -> str:
    uid = str(raw_uid or '').strip()
    if not uid:
        return uid
    if entry is not None and entry.allauth_id == 'openid_connect':
        claims = id_token_claims if isinstance(id_token_claims, dict) else {}
        issuer = str(claims.get('iss') or '').strip()
        if not issuer:
            settings_data = social_app.settings if isinstance(social_app.settings, dict) else {}
            issuer = str(settings_data.get('server_url') or '').strip().rstrip('/')
        if issuer:
            return f'{issuer}|{uid}'
    return uid


def lookup_catalog_slug_for_social_account(provider: str, uid: str) -> str | None:
    """Best-effort docs_slug for JWT display from stored SocialAccount keys."""
    key = str(provider or '').strip().lower()
    if not key:
        return None
    entry = resolve_catalog_slug(key)
    if entry is not None:
        return entry.docs_slug
    if '|' in uid:
        return key
    return resolve_catalog_slug(key) and key or key
