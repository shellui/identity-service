#!/usr/bin/env python3
"""Generate docs/oauth-providers.md from apps/authapi/provider_catalog.json."""

from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / 'apps' / 'authapi' / 'provider_catalog.json'
OUT_PATH = ROOT / 'docs' / 'oauth-providers.md'
# Partial imported by docs/index.md. Docusaurus does not publish files that start with `_`.
LOGOS_PATH = ROOT / 'docs' / '_provider-logos.mdx'

import sys

sys.path.insert(0, str(ROOT))
from tools.catalog_doc_strings_en import CONSOLE_LINK_KIND_EN, EXTRA_SETTING_LABEL_EN  # noqa: E402

# Matches apps.authapi.oauth_idp_policy.COMPANY_CONTROLLED_IDP_SLUGS, plus SAML.
COMPANY_IDP_POLICIES = frozenset({'company_idp_uid_only'})
COMPANY_IDP_PROTOCOLS = frozenset({'SAML'})

# Same setting key, different meaning per provider.
FIELD_LABEL_OVERRIDES: dict[tuple[str, str], str] = {
    ('apple', 'key'): 'Apple Team ID',
}

EMAIL_LINKING_SHORT: dict[str, str] = {
    'github_verified_primary': 'Verified primary email',
    'google_email_verified': 'Verified email in the ID token',
    'microsoft_tenant': 'Tenant check',
    'oidc_email_verified_or_uid_only': 'Verified email in the ID token',
    'twitch_verified_email': 'Email from Twitch',
    'oauth2_email_verified_or_uid_only': 'When the provider marks the email verified',
    'company_idp_uid_only': 'Never',
    'uid_only': 'Trusted domains only',
}

EMAIL_LINKING_LONG: dict[str, str] = {
    'github_verified_primary': (
        'identity-service reads `/user/emails` and links by email only when the primary address is verified. '
        'Without a verified primary email, sign-in stops with an error.'
    ),
    'google_email_verified': (
        'Links by email when the ID token has `email_verified: true` and the same email as the userinfo response.'
    ),
    'microsoft_tenant': (
        'With a dedicated `tenant` (GUID or domain), the ID token `tid` must match it. '
        'With `common` or no tenant, the ID token must carry `xms_edov: true`. '
        'Otherwise sign-in stops with an error, so a personal account cannot claim a work email.'
    ),
    'oidc_email_verified_or_uid_only': (
        'Links by email when the verified ID token has `email_verified: true` and the same email as userinfo. '
        'Otherwise the account is matched by provider account ID only.'
    ),
    'twitch_verified_email': (
        'Twitch returns `email` only for verified addresses, so its presence is the check. '
        'When Twitch omits it, sign-in stops with `oauth_identity_failed`.'
    ),
    'oauth2_email_verified_or_uid_only': (
        'Links by email when the profile has `email_verified: true`. '
        'Otherwise the account is matched by provider account ID only.'
    ),
    'company_idp_uid_only': (
        'Never links by email. The company controls this identity provider, so its email claims are not proof of ownership. '
        'Accounts are matched by provider account ID, scoped to the issuer.'
    ),
    'uid_only': (
        'Matched by SAML NameID only. Email linking needs `trusted_for_verified_domains` and a verified company domain, '
        'see [SAML email linking](saml.md#email-linking).'
    ),
}

# Hand-written notes. Keep them to behavior the code enforces.
PROVIDER_NOTES: dict[str, list[str]] = {
    'apple': [
        'Follow the django-allauth Apple setup: the client ID is your Services ID and the client secret is the Key ID of your Sign in with Apple key.',
        'Paste the `.p8` file content in `certificate_key`. Shellui admin never shows it again.',
        'Apple posts the callback as a form (`form_post`). identity-service handles that on the same callback URL.',
    ],
    'auth0': [
        'Set `AUTH0_URL` to your tenant domain, for example `https://your_tenant.eu.auth0.com`.',
    ],
    'github': [
        'Create an OAuth app and paste the callback URL as the **Authorization callback URL**.',
    ],
    'gitlab': [
        'Leave `gitlab_url` empty for gitlab.com. For a self-hosted GitLab, set its base URL.',
        'A self-hosted GitLab counts as a company identity provider: it never links by email, and account IDs are prefixed with the GitLab base URL.',
    ],
    'google': [
        'Google skips the identity-service account confirmation page by default, because Google already shows its own account picker. '
        'Change this with `OAUTH_SKIP_CONFIRM_PROVIDERS`, see [OAuth login](oauth-login.md#skip-the-confirmation-page).',
    ],
    'keycloak': [
        'Set `server_url` to the realm issuer, for example `https://keycloak.example.com/realms/acme`. identity-service loads the OpenID Connect discovery document from it.',
    ],
    'linkedin': [
        'Enable **Sign In with LinkedIn using OpenID Connect** on the app. The LinkedIn endpoints are fixed in identity-service, so there is nothing else to set.',
    ],
    'microsoft': [
        'Register the app in Microsoft Entra ID. Set `tenant` to your directory (GUID or domain) to accept only your organization, or leave it empty for any Microsoft account.',
    ],
    'okta': [
        'Set `OKTA_BASE_URL` to your Okta org URL, for example `https://acme.okta.com`.',
    ],
    'openid_connect': [
        'Use this entry for any standards-compliant OpenID Connect provider. Set `server_url` to the issuer URL or to its `/.well-known/openid-configuration` URL.',
        'identity-service checks that the discovery document `issuer` matches, and verifies ID tokens against the provider keys.',
    ],
    'saml': [
        'SAML has its own setup and endpoints. Follow [SAML single sign-on](saml.md).',
    ],
    'shopify': [
        'Sign-in needs the store domain. Add it to the authorize request: `GET /api/v1/authorize?provider=shopify&shop=your_store.myshopify.com&…`.',
    ],
    'slack': [
        'Create the app at api.slack.com and add the callback URL under **OAuth & Permissions**.',
    ],
    'twitch': [
        'identity-service requests one scope, `user:read:email`. Authorize and token calls go to `id.twitch.tv` and the profile call to `https://api.twitch.tv/helix/users`. These hosts are fixed: a company URL or scope setting returns `oauth_setting_not_allowed`.',
        'When the Helix user `id` is missing, or the profile request fails, sign-in stops with `token_exchange_failed`. No account is created.',
        'Twitch runs without PKCE. Sign-in relies on the signed OAuth state and the client secret.',
    ],
}


def _glyph_color(hex_color: str) -> str:
    """Brand color, or the text color when the brand is too dark for dark mode."""
    try:
        r, g, b = (int(hex_color[i : i + 2], 16) / 255 for i in (0, 2, 4))
    except ValueError:
        return 'currentColor'
    luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b
    is_grey = max(r, g, b) - min(r, g, b) < 0.1
    if luminance < 0.3 or (is_grey and luminance < 0.5):
        return 'currentColor'
    return f'#{hex_color}'


def _icon(icon: dict, name: str, size: int = 18) -> str:
    # JSX style objects: docs.shellui.com renders these pages as MDX, which
    # rejects a plain HTML style string.
    if icon.get('source') == 'simple-icons' and icon.get('slug'):
        url = f"https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/{icon['slug']}.svg"
        color = _glyph_color(str(icon.get('hex') or '000000').lstrip('#'))
        mask = f'url({url}) center / contain no-repeat'
        return (
            f"<span role=\"img\" aria-label=\"{name}\" style={{{{display:'inline-block',width:{size},height:{size},"
            f"verticalAlign:'middle',flexShrink:0,background:'{color}',WebkitMask:'{mask}',mask:'{mask}'}}}} />"
        )
    return (
        f"<span aria-hidden=\"true\" style={{{{display:'inline-flex',alignItems:'center',justifyContent:'center',"
        f"width:{size},height:{size},verticalAlign:'middle',flexShrink:0,borderRadius:'50%',"
        f"background:'var(--ifm-color-emphasis-300)',fontSize:{size // 2 + 2},fontWeight:700}}}}>{name[:1]}</span>"
    )


def _field_label(slug: str, name: str) -> str:
    return FIELD_LABEL_OVERRIDES.get((slug, name)) or EXTRA_SETTING_LABEL_EN.get(name, name)


def _settings_cell(entry: dict) -> str:
    schema = entry.get('extra_settings_schema') or []
    if not schema:
        return 'Client ID and secret'
    slug = entry['docs_slug']
    if entry.get('protocol') == 'SAML':
        required = [f'`{field["name"]}`' for field in schema if field.get('required')]
        return f"{', '.join(required)}, see [SAML](saml.md)"
    parts = []
    for field in schema:
        suffix = '' if field.get('required') else ' (optional)'
        parts.append(f"`{field['name']}`{suffix}")
    return 'Client ID, secret, ' + ', '.join(parts)


def _console_lines(console_url: list) -> list[str]:
    """Plain-text console URLs (avoid lychee failures on IdP login redirects)."""
    lines = []
    for item in console_url or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get('url') or '').strip()
        if not url.startswith('http'):
            continue
        kind = str(item.get('kind') or 'other')
        label = CONSOLE_LINK_KIND_EN.get(kind, kind.replace('_', ' ').title())
        if item.get('form') == 'template' and item.get('placeholders'):
            placeholders = ', '.join(f'`{name}`' for name in item['placeholders'])
            label = f'{label} (replace {placeholders})'
        lines.append(f'{label}: `{url}`')
    return lines


def _is_company_idp(entry: dict) -> bool:
    return (
        entry.get('email_link_policy') in COMPANY_IDP_POLICIES
        or entry.get('protocol') in COMPANY_IDP_PROTOCOLS
    )


def _anchor(entry: dict) -> str:
    return str(entry.get('name') or entry['docs_slug']).lower().replace(' ', '-')


def render_table(entries: list[dict]) -> list[str]:
    lines = [
        '| Provider | Catalog ID | Protocol | Company settings | Links by email |',
        '| --- | --- | --- | --- | --- |',
    ]
    for entry in entries:
        policy = entry.get('email_link_policy') or 'uid_only'
        lines.append(
            f"| {_icon(entry.get('icon') or {}, entry.get('name') or '')} [{entry.get('name')}](#{_anchor(entry)}) "
            f"| `{entry['docs_slug']}` "
            f"| {entry.get('protocol') or '-'} "
            f"| {_settings_cell(entry)} "
            f"| {EMAIL_LINKING_SHORT.get(policy, 'Never')} |"
        )
    return lines


def render_provider_section(entry: dict) -> list[str]:
    slug = entry['docs_slug']
    policy = entry.get('email_link_policy') or 'uid_only'
    lines = [f"### {entry.get('name')}", '']
    for note in PROVIDER_NOTES.get(slug, []):
        lines.extend([note, ''])
    facts = [f'- **Catalog ID**: `{slug}`']
    console = _console_lines(entry.get('console_url') or [])
    if len(console) == 1:
        facts.append(f"- **Create the app**: {console[0].split(': ', 1)[1]}")
    elif console:
        facts.append('- **Create the app**:')
        facts.extend(f'  - {line}' for line in console)
    schema = entry.get('extra_settings_schema') or []
    if schema and entry.get('protocol') != 'SAML':
        settings = []
        for field in schema:
            flags = 'required' if field.get('required') else 'optional'
            if field.get('secret'):
                flags += ', secret'
            settings.append(f"`{field['name']}` ({_field_label(slug, field['name'])}, {flags})")
        facts.append(f"- **Settings**: {', '.join(settings)}")
    facts.append(f'- **Email linking**: {EMAIL_LINKING_LONG.get(policy, EMAIL_LINKING_LONG["uid_only"])}')
    facts.append(
        '- **Apps per company**: '
        + ('several, one per identity provider' if entry.get('multiple_allowed') else 'one')
    )
    if entry.get('docs_url'):
        facts.append(f"- **Reference**: [django-allauth {entry.get('name')} docs]({entry['docs_url']})")
    lines.extend(facts)
    lines.append('')
    return lines


def render_logos(supported: list[dict], oauth_count: int) -> list[str]:
    chip_style = (
        "{{display:'inline-flex',alignItems:'center',gap:'0.45rem',padding:'0.3rem 0.75rem',"
        "border:'1px solid var(--ifm-color-emphasis-300)',borderRadius:999,fontSize:'0.875rem',"
        "fontWeight:500,color:'inherit',textDecoration:'none'}}"
    )
    lines = [
        "import Link from '@docusaurus/Link';",
        '',
        '{/* Generated by tools/render_oauth_providers_doc.py from apps/authapi/provider_catalog.json. Do not edit. */}',
        '',
        "<div style={{display:'flex',flexWrap:'wrap',gap:'0.5rem',margin:'0.75rem 0 0.5rem'}}>",
    ]
    for entry in supported:
        name = entry.get('name') or entry['docs_slug']
        lines.append(
            f'  <Link to="/identity/oauth-providers#{_anchor(entry)}" style={chip_style}>'
            f"{_icon(entry.get('icon') or {}, name, 16)} {name}</Link>"
        )
    lines.extend(
        [
            '</div>',
            '',
            f'{oauth_count} OAuth and OpenID Connect providers plus SAML 2.0, configured per company in Shellui admin.',
        ]
    )
    return lines


def main() -> int:
    catalog = json.loads(CATALOG_PATH.read_text(encoding='utf-8'))
    providers = catalog.get('providers') or []
    supported = sorted(
        (entry for entry in providers if entry.get('supported') and not entry.get('legacy')),
        key=lambda item: str(item.get('name') or '').lower(),
    )
    social = [entry for entry in supported if not _is_company_idp(entry)]
    company = [entry for entry in supported if _is_company_idp(entry)]
    oauth_count = sum(1 for entry in supported if entry.get('protocol') != 'SAML')
    unavailable = len(providers) - len(supported)

    lines = [
        '---',
        'description: The sign-in providers identity-service supports, the settings each one needs, and when each one links accounts by email.',
        '---',
        '',
        '# OAuth providers',
        '',
        f'identity-service supports {len(supported)} sign-in providers: {oauth_count} OAuth 2.0 and OpenID Connect providers, plus SAML 2.0. '
        'Each company creates its own app at the provider, then adds the credentials in Shellui admin under **OAuth setup**. '
        'Shellui admin offers exactly the providers on this page. For the sign-in flow itself, see [OAuth login](oauth-login.md).',
        '',
        '## Register the callback URL',
        '',
        'Every provider app uses the same callback URL, on identity-service. Register it with no query string:',
        '',
        '| Environment | Callback URL |',
        '| --- | --- |',
        '| Local | `http://localhost:8000/api/v1/oauth/callback` |',
        '| Production | `https://auth.example.com/api/v1/oauth/callback` |',
        '',
        'Replace `auth.example.com` with your identity-service host. '
        "Do not register your shell's `/login/callback` URL at the provider: identity-service redirects there after sign-in. "
        'django-allauth docs mention `/accounts/<provider>/login/callback/`, a path identity-service does not serve.',
        '',
        '## Social and developer accounts',
        '',
        'People sign in with an account they already have at a public provider. Use these for products open to anyone.',
        '',
        *render_table(social),
        '',
        '## Company identity providers',
        '',
        "These providers are run by the company itself, for example its Okta org or Keycloak realm. Use them for workforce single sign-on (SSO). "
        'identity-service never links these sign-ins to an existing user by email.',
        '',
        *render_table(company),
        '',
        '## How email linking works',
        '',
        'The first time someone signs in with a provider, identity-service looks for an existing user with the same provider account. '
        'When there is none, it can attach the sign-in to an existing user with the same email, but only when the provider proves the email belongs to that person. '
        'The **Links by email** column shows the proof each provider needs. Without it, identity-service matches by provider account ID only and never takes over another user by email.',
        '',
        '## Provider setup',
        '',
        'Each section lists where to create the app, the extra settings Shellui admin asks for, and provider-specific behavior.',
        '',
    ]
    for entry in supported:
        lines.extend(render_provider_section(entry))
    lines.extend(
        [
            '## Providers that are not available',
            '',
            f'django-allauth ships {unavailable} more provider modules. '
            'They stay in `GET /api/v1/oauth-provider-catalog` with `supported: false` and an `unsupported_reason`, '
            'but Shellui admin hides them and `POST /api/v1/oauth-social-apps` refuses them with **400**. '
            'A provider becomes available once identity-service has an adapter for it, covered by a hand-written sign-in test.',
            '',
            '## Update this page',
            '',
            'This page is generated from `apps/authapi/provider_catalog.json` '
            f"(catalog version {catalog.get('catalog_version')}, django-allauth {catalog.get('allauth_version')}). "
            'After a catalog change, regenerate it:',
            '',
            '```bash',
            'uv run python tools/render_oauth_providers_doc.py',
            '```',
            '',
            'CI fails when this page does not match the catalog. Edit provider notes in `tools/render_oauth_providers_doc.py`, not here.',
        ]
    )

    OUT_PATH.write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')
    print(f'Wrote {OUT_PATH}')
    LOGOS_PATH.write_text('\n'.join(render_logos(supported, oauth_count)) + '\n', encoding='utf-8')
    print(f'Wrote {LOGOS_PATH}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
