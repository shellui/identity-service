#!/usr/bin/env python3
"""Build apps/authapi/provider_catalog.json from the scraped allauth provider dataset."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.catalog_i18n import (  # noqa: E402
    normalize_console_urls,
    normalize_extra_settings_schema,
)

DEFAULT_SOURCE = ROOT / 'tools' / 'data' / 'allauth_providers_source.json'
E2E_SLUGS_PATH = ROOT / 'tools' / 'data' / 'oauth_e2e_covered_slugs.json'
OUT_PATH = ROOT / 'apps' / 'authapi' / 'provider_catalog.json'

EMAIL_POLICY_BY_SLUG: dict[str, str] = {
    'github': 'github_verified_primary',
    'google': 'google_email_verified',
    'microsoft': 'microsoft_tenant',
    'discord': 'discord_email_verified',
    'kakao': 'kakao_email_verified',
}

EMAIL_POLICY_BY_PROTOCOL: dict[str, str] = {
    'OAuth2': 'oauth2_email_verified_or_uid_only',
    'OpenID Connect': 'oidc_email_verified_or_uid_only',
}

EXTRA_SCHEMA_OVERRIDES: dict[str, list[dict]] = {
    'microsoft': [{'name': 'tenant', 'type': 'string', 'required': False, 'secret': False}],
    'auth0': [{'name': 'AUTH0_URL', 'type': 'url', 'required': True, 'secret': False}],
    'apple': [
        {'name': 'key', 'type': 'string', 'required': True, 'secret': False},
        {'name': 'certificate_key', 'type': 'text', 'required': True, 'secret': True},
    ],
    'okta': [{'name': 'OKTA_BASE_URL', 'type': 'url', 'required': True, 'secret': False}],
    'gitlab': [{'name': 'gitlab_url', 'type': 'url', 'required': False, 'secret': False}],
    'nextcloud': [{'name': 'server', 'type': 'url', 'required': True, 'secret': False}],
    'amazon_cognito': [{'name': 'DOMAIN', 'type': 'url', 'required': True, 'secret': False}],
    'jupyterhub': [{'name': 'API_URL', 'type': 'url', 'required': True, 'secret': False}],
    'lemonldap': [{'name': 'LEMONLDAP_URL', 'type': 'url', 'required': True, 'secret': False}],
    'netiq': [{'name': 'NETIQ_URL', 'type': 'url', 'required': True, 'secret': False}],
    'gumroad': [{'name': 'GUMROAD_URL', 'type': 'url', 'required': False, 'secret': False}],
    'salesforce': [{'name': 'key', 'type': 'string', 'required': True, 'secret': False}],
    'edx': [{'name': 'EDX_URL', 'type': 'url', 'required': True, 'secret': False}],
    'mailcow': [{'name': 'SERVER', 'type': 'url', 'required': True, 'secret': False}],
    'mediawiki': [{'name': 'REST_API', 'type': 'url', 'required': True, 'secret': False}],
    'sharefile': [{'name': 'API_URL', 'type': 'url', 'required': True, 'secret': False}],
    'gitea': [{'name': 'GITEA_URL', 'type': 'url', 'required': True, 'secret': False}],
    'github_enterprise': [{'name': 'GITHUB_URL', 'type': 'url', 'required': True, 'secret': False}],
}

OIDC_SERVER_URL_SLUGS = frozenset(
    {
        'openid_connect',
        'keycloak',
        'authelia',
        'cern',
        'linkedin',
    }
)


def _default_extra_schema(entry: dict) -> list[dict]:
    slug = entry['docs_slug']
    if slug in EXTRA_SCHEMA_OVERRIDES:
        return list(EXTRA_SCHEMA_OVERRIDES[slug])
    if slug in OIDC_SERVER_URL_SLUGS or entry.get('id') == 'openid_connect':
        fields = [
            {'name': 'server_url', 'type': 'url', 'required': True, 'secret': False},
        ]
        if entry.get('provider_id'):
            fields.insert(
                0,
                {'name': 'provider_id', 'type': 'string', 'required': True, 'secret': False},
            )
        return fields
    return []


def _email_link_policy(entry: dict) -> str:
    slug = entry['docs_slug']
    if slug in EMAIL_POLICY_BY_SLUG:
        return EMAIL_POLICY_BY_SLUG[slug]
    return EMAIL_POLICY_BY_PROTOCOL.get(entry.get('protocol') or '', 'uid_only')


def _installed_provider_apps() -> frozenset[str]:
    apps_path = ROOT / 'config' / 'allauth_provider_apps.py'
    namespace: dict = {}
    exec(apps_path.read_text(encoding='utf-8'), namespace)  # noqa: S102
    return frozenset(namespace.get('ALLAUTH_SOCIALACCOUNT_PROVIDER_APPS', ()))


def _app_has_oauth2_provider(app_path: str | None, installed: frozenset[str]) -> bool:
    if not app_path or not app_path.startswith('allauth.socialaccount.providers.'):
        return False
    if app_path.endswith('.oauth2'):
        return False
    return app_path in installed


def _supported(entry: dict, installed: frozenset[str]) -> tuple[bool, str | None]:
    if entry.get('legacy'):
        return False, 'Legacy provider; use the replacement listed in the catalog.'
    protocol = entry.get('protocol') or ''
    if protocol in {'OAuth1', 'SAML', 'other'}:
        return False, f'Protocol {protocol} is not supported by the identity-hosted OAuth callback yet.'
    if entry.get('docs_slug') == 'oauth2' or (entry.get('app') or '').endswith('.oauth2'):
        return False, 'Generic OAuth 2.0 requires custom endpoints; not wired in this release.'
    if protocol not in {'OAuth2', 'OpenID Connect'}:
        return False, 'Unsupported protocol.'
    if not _app_has_oauth2_provider(entry.get('app'), installed):
        return False, 'No OAuth2 adapter is available for this provider module.'
    e2e_slugs = _e2e_covered_slugs()
    if entry.get('docs_slug') not in e2e_slugs:
        return False, 'Missing end-to-end OAuth adapter test coverage.'
    return True, None


def _e2e_covered_slugs() -> frozenset[str]:
    if not E2E_SLUGS_PATH.is_file():
        return frozenset()
    data = json.loads(E2E_SLUGS_PATH.read_text(encoding='utf-8'))
    if isinstance(data, list):
        return frozenset(str(item).strip().lower() for item in data if str(item).strip())
    return frozenset()


def build_entry(raw: dict, *, installed: frozenset[str]) -> dict:
    supported, unsupported_reason = _supported(raw, installed)
    provider_id = raw.get('provider_id')
    if raw.get('id') == 'openid_connect' and not provider_id and raw.get('docs_slug') != 'openid_connect':
        provider_id = raw.get('docs_slug')
    icon = raw.get('icon') or {}
    if icon.get('source') != 'simple-icons':
        icon = {
            'source': 'fallback',
            'slug': icon.get('slug') or 'log-in',
            'hex': icon.get('hex') or '64748B',
            'title': raw.get('name') or raw.get('docs_slug'),
        }
    return {
        'docs_slug': raw['docs_slug'],
        'id': raw.get('id'),
        'provider_id': provider_id,
        'name': raw.get('name'),
        'tier': raw.get('tier'),
        'legacy': bool(raw.get('legacy')),
        'replaced_by': raw.get('replaced_by'),
        'protocol': raw.get('protocol'),
        'app': raw.get('app'),
        'supported': supported,
        'unsupported_reason': unsupported_reason,
        'email_link_policy': _email_link_policy(raw),
        'docs_url': raw.get('docs_url'),
        'console_url': normalize_console_urls(raw.get('console_url') or []),
        'allauth_callback_path': raw.get('expected_callback_path') or raw.get('callback_path'),
        'extra_settings_schema': normalize_extra_settings_schema(_default_extra_schema(raw)),
        'icon': icon,
        'notes': raw.get('notes') or '',
    }


def main() -> int:
    source = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SOURCE
    if not source.is_file():
        print(f'Missing source dataset: {source}', file=sys.stderr)
        return 1
    raw_entries = json.loads(source.read_text(encoding='utf-8'))
    installed = _installed_provider_apps()
    installed_allauth = importlib.metadata.version('django-allauth')
    catalog = {
        'catalog_version': '2',
        'allauth_version': installed_allauth,
        'providers': [build_entry(item, installed=installed) for item in raw_entries],
    }
    OUT_PATH.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    supported = sum(1 for p in catalog['providers'] if p['supported'])
    print(f'Wrote {len(catalog["providers"])} providers ({supported} supported) to {OUT_PATH}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
