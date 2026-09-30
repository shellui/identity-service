"""Load and query the checked-in OAuth provider catalog."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from apps.actions.ssrf import SSRFError, resolve_webhook_endpoint

CATALOG_PATH = Path(__file__).resolve().parent / 'provider_catalog.json'


@dataclass(frozen=True)
class ExtraSettingField:
    name: str
    type: str
    required: bool
    secret: bool

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ExtraSettingField:
        return cls(
            name=str(raw['name']),
            type=str(raw.get('type') or 'string'),
            required=bool(raw.get('required')),
            secret=bool(raw.get('secret')),
        )


@dataclass(frozen=True)
class ProviderCatalogEntry:
    docs_slug: str
    allauth_id: str
    provider_id: str | None
    name: str
    tier: str
    legacy: bool
    hidden: bool
    replaced_by: str | None
    protocol: str
    app: str
    supported: bool
    unsupported_reason: str | None
    email_link_policy: str
    docs_url: str
    console_url: list[dict[str, Any]]
    allauth_callback_path: str | None
    extra_settings_schema: tuple[ExtraSettingField, ...]
    icon: dict[str, Any]
    notes: str
    multiple_allowed: bool

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ProviderCatalogEntry:
        schema = tuple(
            ExtraSettingField.from_dict(item)
            for item in (raw.get('extra_settings_schema') or [])
            if isinstance(item, dict) and item.get('name')
        )
        return cls(
            docs_slug=str(raw['docs_slug']),
            allauth_id=str(raw.get('id') or raw['docs_slug']),
            provider_id=(str(raw['provider_id']).strip() or None) if raw.get('provider_id') else None,
            name=str(raw.get('name') or raw['docs_slug']),
            tier=str(raw.get('tier') or 'other'),
            legacy=bool(raw.get('legacy')),
            hidden=bool(raw.get('hidden')),
            replaced_by=(str(raw['replaced_by']).strip() or None) if raw.get('replaced_by') else None,
            protocol=str(raw.get('protocol') or ''),
            app=str(raw.get('app') or ''),
            supported=bool(raw.get('supported')),
            unsupported_reason=(str(raw['unsupported_reason']).strip() or None)
            if raw.get('unsupported_reason')
            else None,
            email_link_policy=str(raw.get('email_link_policy') or 'uid_only'),
            docs_url=str(raw.get('docs_url') or ''),
            console_url=list(raw.get('console_url') or []),
            allauth_callback_path=raw.get('allauth_callback_path'),
            extra_settings_schema=schema,
            icon=dict(raw.get('icon') or {}),
            notes=str(raw.get('notes') or ''),
            multiple_allowed=bool(raw.get('multiple_allowed')),
        )

    def social_app_provider(self) -> str:
        return self.allauth_id

    def social_app_provider_id(self) -> str:
        if self.allauth_id == 'openid_connect':
            return self.provider_id or self.docs_slug
        return self.provider_id or ''


@dataclass(frozen=True)
class ProviderCatalog:
    catalog_version: str
    allauth_version: str
    providers: tuple[ProviderCatalogEntry, ...]

    def by_slug(self) -> dict[str, ProviderCatalogEntry]:
        return {entry.docs_slug: entry for entry in self.providers}

    def supported_slugs(self) -> frozenset[str]:
        return frozenset(entry.docs_slug for entry in self.providers if entry.supported)


def load_provider_catalog() -> ProviderCatalog:
    raw = json.loads(CATALOG_PATH.read_text(encoding='utf-8'))
    providers = tuple(
        ProviderCatalogEntry.from_dict(item)
        for item in raw.get('providers', [])
        if isinstance(item, dict) and item.get('docs_slug')
    )
    return ProviderCatalog(
        catalog_version=str(raw.get('catalog_version') or '1'),
        allauth_version=str(raw.get('allauth_version') or ''),
        providers=providers,
    )


@lru_cache(maxsize=1)
def get_provider_catalog() -> ProviderCatalog:
    return load_provider_catalog()


def get_catalog_entry(docs_slug: str) -> ProviderCatalogEntry | None:
    key = str(docs_slug or '').strip().lower()
    if not key:
        return None
    return get_provider_catalog().by_slug().get(key)


def resolve_catalog_slug(value: str) -> ProviderCatalogEntry | None:
    """Resolve authorize/admin provider key (docs_slug or legacy allauth id)."""
    key = str(value or '').strip().lower()
    if not key:
        return None
    catalog = get_provider_catalog()
    direct = catalog.by_slug().get(key)
    if direct is not None:
        return direct
    for entry in catalog.providers:
        if entry.allauth_id.lower() == key and entry.docs_slug == entry.allauth_id:
            return entry
    return None


def supported_oauth_provider_slugs() -> frozenset[str]:
    return get_provider_catalog().supported_slugs()


def validate_extra_settings(
    entry: ProviderCatalogEntry,
    extra: dict[str, Any] | None,
    *,
    partial: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Return normalized settings for SocialApp.settings and validation errors."""
    errors: list[str] = []
    incoming = dict(extra or {})
    normalized: dict[str, Any] = {}
    for field in entry.extra_settings_schema:
        if field.secret and field.name not in incoming and partial:
            continue
        if field.name not in incoming:
            if field.required and not partial:
                errors.append(f'Missing required setting {field.name!r}.')
            continue
        value = incoming[field.name]
        if value is None or (isinstance(value, str) and not value.strip()):
            if field.required and not partial:
                errors.append(f'Setting {field.name!r} cannot be empty.')
            continue
        normalized_value = value.strip() if isinstance(value, str) else value
        if field.type == 'url' and isinstance(normalized_value, str):
            try:
                resolve_webhook_endpoint(normalized_value, allow_private=False)
            except SSRFError as exc:
                errors.append(f'{field.name}: {exc}')
                continue
        normalized[field.name] = normalized_value
    for key in incoming:
        if key not in {f.name for f in entry.extra_settings_schema}:
            errors.append(f'Unknown extra setting {key!r}.')
    if entry.docs_slug == 'linkedin':
        from apps.authapi.oauth_linkedin import LINKEDIN_OIDC_SERVER_URL

        if 'server_url' in incoming:
            errors.append('LinkedIn does not accept a custom server_url.')
        normalized['server_url'] = LINKEDIN_OIDC_SERVER_URL

    normalized['catalog_slug'] = entry.docs_slug
    return normalized, errors


def catalog_entry_for_social_app(social_app) -> ProviderCatalogEntry | None:
    settings_data = social_app.settings if isinstance(getattr(social_app, 'settings', None), dict) else {}
    slug = str(settings_data.get('catalog_slug') or '').strip().lower()
    if slug:
        return get_catalog_entry(slug)
    provider = str(getattr(social_app, 'provider', '') or '').strip().lower()
    provider_id = str(getattr(social_app, 'provider_id', '') or '').strip().lower()
    if provider == 'openid_connect' and provider_id:
        return get_catalog_entry(provider_id) or get_catalog_entry('openid_connect')
    return resolve_catalog_slug(provider)
