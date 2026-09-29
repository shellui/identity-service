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
    'microsoft': [
        {
            'name': 'tenant',
            'label': 'Tenant ID',
            'type': 'string',
            'required': False,
            'secret': False,
            'help_text': 'Entra ID tenant GUID, or common for multi-tenant apps.',
        },
    ],
    'auth0': [
        {
            'name': 'AUTH0_URL',
            'label': 'Auth0 domain URL',
            'type': 'url',
            'required': True,
            'secret': False,
            'help_text': 'Base URL of your Auth0 tenant, for example https://your-tenant.auth0.com',
        },
    ],
    'apple': [
        {
            'name': 'key',
            'label': 'Apple Team ID',
            'type': 'string',
            'required': True,
            'secret': False,
        },
        {
            'name': 'certificate_key',
            'label': 'Sign in with Apple private key (.p8)',
            'type': 'text',
            'required': True,
            'secret': True,
        },
    ],
    'okta': [
        {
            'name': 'OKTA_BASE_URL',
            'label': 'Okta org URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'gitlab': [
        {
            'name': 'gitlab_url',
            'label': 'GitLab base URL',
            'type': 'url',
            'required': False,
            'secret': False,
            'help_text': 'Self-hosted GitLab URL. Defaults to https://gitlab.com.',
        },
    ],
    'nextcloud': [
        {
            'name': 'server',
            'label': 'Nextcloud server URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'amazon_cognito': [
        {
            'name': 'DOMAIN',
            'label': 'Cognito domain URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'jupyterhub': [
        {
            'name': 'API_URL',
            'label': 'JupyterHub API URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'lemonldap': [
        {
            'name': 'LEMONLDAP_URL',
            'label': 'LemonLDAP base URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'netiq': [
        {
            'name': 'NETIQ_URL',
            'label': 'NetIQ Access Manager URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'gumroad': [
        {
            'name': 'GUMROAD_URL',
            'label': 'Gumroad base URL',
            'type': 'url',
            'required': False,
            'secret': False,
        },
    ],
    'salesforce': [
        {
            'name': 'key',
            'label': 'Salesforce login host',
            'type': 'string',
            'required': True,
            'secret': False,
            'help_text': 'Salesforce domain used as SocialApp key (for example login.salesforce.com).',
        },
    ],
    'edx': [
        {
            'name': 'API_URL',
            'label': 'edX API URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'mailcow': [
        {
            'name': 'API_URL',
            'label': 'Mailcow API URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'mediawiki': [
        {
            'name': 'MEDIAWIKI_URL',
            'label': 'MediaWiki URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'sharefile': [
        {
            'name': 'API_URL',
            'label': 'ShareFile API URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'gitea': [
        {
            'name': 'GITEA_URL',
            'label': 'Gitea URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
    'github_enterprise': [
        {
            'name': 'GITHUB_URL',
            'label': 'GitHub Enterprise URL',
            'type': 'url',
            'required': True,
            'secret': False,
        },
    ],
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
            {
                'name': 'server_url',
                'label': 'OpenID Connect issuer URL',
                'type': 'url',
                'required': True,
                'secret': False,
                'help_text': 'Issuer URL or .well-known/openid-configuration URL.',
            },
        ]
        if entry.get('provider_id'):
            fields.insert(
                0,
                {
                    'name': 'provider_id',
                    'label': 'Provider ID',
                    'type': 'string',
                    'required': True,
                    'secret': False,
                    'help_text': 'Sub-provider id stored on the SocialApp (openid_connect).',
                },
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
        'console_url': raw.get('console_url') or [],
        'allauth_callback_path': raw.get('expected_callback_path') or raw.get('callback_path'),
        'extra_settings_schema': _default_extra_schema(raw),
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
        'catalog_version': '1',
        'allauth_version': installed_allauth,
        'providers': [build_entry(item, installed=installed) for item in raw_entries],
    }
    OUT_PATH.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    supported = sum(1 for p in catalog['providers'] if p['supported'])
    print(f'Wrote {len(catalog["providers"])} providers ({supported} supported) to {OUT_PATH}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
