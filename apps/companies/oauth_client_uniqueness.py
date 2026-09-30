"""Company-scoped OAuth SocialApp uniqueness (catalog slug and OIDC instance keys)."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp

from apps.authapi.oauth import social_app_catalog_slug
from apps.authapi.provider_registry import ProviderCatalogEntry, get_catalog_entry, resolve_catalog_slug
from apps.companies.models import CompanyOAuthClient


def catalog_entry_multiple_allowed(entry: ProviderCatalogEntry) -> bool:
    return bool(entry.multiple_allowed)


def _normalized_server_url(settings: dict) -> str:
    return str(settings.get('server_url') or '').strip().lower()


def _normalized_provider_id(
    entry: ProviderCatalogEntry,
    *,
    social_app: SocialApp,
    settings: dict,
) -> str:
    raw = (
        str(getattr(social_app, 'provider_id', '') or '').strip()
        or str(settings.get('provider_id') or '').strip()
        or entry.social_app_provider_id()
    )
    return raw.lower()


def compute_oauth_client_dedupe_key(
    social_app: SocialApp,
    *,
    catalog_slug: str | None = None,
    entry: ProviderCatalogEntry | None = None,
) -> str | None:
    slug = str(catalog_slug or social_app_catalog_slug(social_app)).strip().lower()
    if not slug:
        return None
    resolved_entry = entry or get_catalog_entry(slug) or resolve_catalog_slug(slug)
    if resolved_entry is None:
        return slug
    if resolved_entry.allauth_id == 'saml':
        settings = social_app.settings if isinstance(getattr(social_app, 'settings', None), dict) else {}
        idp = settings.get('idp') if isinstance(settings.get('idp'), dict) else {}
        entity = str(idp.get('entity_id') or '').strip().lower()
        return f'saml\x1f{entity}' if entity else None
    if catalog_entry_multiple_allowed(resolved_entry):
        settings = social_app.settings if isinstance(getattr(social_app, 'settings', None), dict) else {}
        provider_id = _normalized_provider_id(resolved_entry, social_app=social_app, settings=settings)
        server = _normalized_server_url(settings)
        return f'{slug}\x1f{provider_id}\x1f{server}'
    return slug


def sync_company_oauth_client_uniqueness_fields(row: CompanyOAuthClient) -> None:
    app = row.social_app
    slug = social_app_catalog_slug(app)
    row.catalog_slug = slug
    row.dedupe_key = compute_oauth_client_dedupe_key(app, catalog_slug=slug)


def find_duplicate_company_oauth_client(
    company_id: int,
    *,
    dedupe_key: str | None,
    exclude_company_oauth_client_id: int | None = None,
) -> CompanyOAuthClient | None:
    if not dedupe_key:
        return None
    qs = CompanyOAuthClient.objects.filter(company_id=company_id, dedupe_key=dedupe_key).select_related(
        'social_app'
    )
    if exclude_company_oauth_client_id is not None:
        qs = qs.exclude(pk=exclude_company_oauth_client_id)
    return qs.order_by('id').first()


def compute_dedupe_key_for_new_app(
    entry: ProviderCatalogEntry,
    *,
    settings: dict,
) -> str | None:
    app = SocialApp(
        provider=entry.allauth_id,
        provider_id=entry.social_app_provider_id(),
        settings=settings,
    )
    return compute_oauth_client_dedupe_key(app, catalog_slug=entry.docs_slug, entry=entry)


def find_duplicate_for_social_app(
    company_id: int,
    social_app: SocialApp,
    *,
    exclude_company_oauth_client_id: int | None = None,
) -> CompanyOAuthClient | None:
    dedupe_key = compute_oauth_client_dedupe_key(social_app)
    return find_duplicate_company_oauth_client(
        company_id,
        dedupe_key=dedupe_key,
        exclude_company_oauth_client_id=exclude_company_oauth_client_id,
    )
