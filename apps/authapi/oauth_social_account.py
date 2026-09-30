"""SocialAccount storage keys and request-scoped SocialApp selection for OAuth."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp

from apps.authapi.oauth_request_context import get_bound_oauth_social_app as _ctx_bound_app
from apps.authapi.provider_registry import ProviderCatalogEntry, resolve_catalog_slug

REQUEST_SOCIAL_APP_ATTR = 'shellui_oauth_social_app'


def bind_oauth_social_app(request, social_app: SocialApp) -> None:
    setattr(request, REQUEST_SOCIAL_APP_ATTR, social_app)


def get_bound_oauth_social_app(request) -> SocialApp | None:
    bound = getattr(request, REQUEST_SOCIAL_APP_ATTR, None)
    if isinstance(bound, SocialApp):
        return bound
    return _ctx_bound_app()


def saml_social_account_provider_key(social_app: SocialApp) -> str:
    return f'saml-{int(social_app.pk)}'


def social_account_provider_key(*, entry: ProviderCatalogEntry | None, social_app: SocialApp) -> str:
    if entry is not None and entry.allauth_id == 'openid_connect':
        sub = str(getattr(social_app, 'provider_id', '') or entry.social_app_provider_id()).strip()
        return sub or entry.docs_slug
    if entry is not None and entry.allauth_id == 'saml':
        return saml_social_account_provider_key(social_app)
    if entry is not None:
        return entry.allauth_id
    if str(social_app.provider).strip().lower() == 'saml':
        return saml_social_account_provider_key(social_app)
    return str(social_app.provider).strip().lower()


def _scoped_issuer(entry: ProviderCatalogEntry, social_app: SocialApp, claims: dict) -> str:
    """Issuer or host prefix for SocialAccount.uid. Empty means the raw uid is stored."""
    settings_data = social_app.settings if isinstance(social_app.settings, dict) else {}
    if entry.allauth_id == 'openid_connect':
        issuer = str(claims.get('iss') or '').strip()
        if not issuer:
            issuer = str(settings_data.get('server_url') or '').strip().rstrip('/')
        return issuer
    if entry.allauth_id == 'okta':
        issuer = str(claims.get('iss') or '').strip().rstrip('/')
        if not issuer:
            issuer = str(settings_data.get('OKTA_BASE_URL') or '').strip().rstrip('/')
        return issuer
    if entry.allauth_id == 'auth0':
        issuer = str(claims.get('iss') or '').strip().rstrip('/')
        if not issuer:
            issuer = str(settings_data.get('AUTH0_URL') or '').strip().rstrip('/')
        return issuer
    if entry.docs_slug == 'gitlab':
        from apps.authapi.oauth_provider_urls import gitlab_base_url, is_self_hosted_gitlab

        if is_self_hosted_gitlab(social_app):
            return gitlab_base_url(social_app)
    return ''


def compose_social_account_uid(
    *,
    entry: ProviderCatalogEntry | None,
    social_app: SocialApp,
    raw_uid: str,
    id_token_claims: dict | None = None,
) -> str:
    uid = str(raw_uid or '').strip()
    if not uid or entry is None:
        return uid
    if entry.allauth_id == 'saml':
        settings_data = social_app.settings if isinstance(social_app.settings, dict) else {}
        idp = settings_data.get('idp') if isinstance(settings_data.get('idp'), dict) else {}
        entity_id = str(idp.get('entity_id') or '').strip()
        if entity_id:
            return f'{entity_id}|{uid}'
    claims = id_token_claims if isinstance(id_token_claims, dict) else {}
    issuer = _scoped_issuer(entry, social_app, claims)
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
