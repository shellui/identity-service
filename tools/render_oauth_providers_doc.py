#!/usr/bin/env python3
"""Generate docs/oauth-providers.md from apps/authapi/provider_catalog.json."""

from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / 'apps' / 'authapi' / 'provider_catalog.json'
OUT_PATH = ROOT / 'docs' / 'oauth-providers.md'

import sys

sys.path.insert(0, str(ROOT))
from tools.catalog_doc_strings_en import CONSOLE_LINK_KIND_EN, EXTRA_SETTING_LABEL_EN  # noqa: E402

TIER_HEADINGS = {
    'popular': 'Popular',
    'generic': 'Generic protocols',
    'other': 'All others',
}


def _icon_cell(icon: dict) -> str:
    if icon.get('source') == 'simple-icons' and icon.get('slug'):
        slug = icon['slug']
        hex_color = str(icon.get('hex') or '000000').lstrip('#')
        return (
            f'<img src="https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/{slug}.svg" '
            # JSX style object: docs.shellui.com renders this page as MDX, which
            # rejects a plain HTML style string.
            f'width="20" height="20" alt="" '
            f"style={{{{verticalAlign:'middle',background:'#{hex_color}'}}}} />"
        )
    return '🔑'


def _console_links(console_url: list) -> str:
    """Plain-text console URLs (avoid lychee failures on IdP login redirects)."""
    links = []
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
            label = f'{label} (template: {placeholders})'
        links.append(f'{label}: `{url}`')
    return '<br />'.join(links) if links else '-'


def _extra_settings(entry: dict) -> str:
    schema = entry.get('extra_settings_schema') or []
    if not schema:
        return '-'
    parts = []
    for field in schema:
        req = 'required' if field.get('required') else 'optional'
        secret = ' (secret)' if field.get('secret') else ''
        name = field['name']
        title = EXTRA_SETTING_LABEL_EN.get(name, name)
        parts.append(f"{title} (`{name}`) ({req}{secret})")
    return ', '.join(parts)


def render_provider_row(entry: dict) -> str:
    supported = 'Yes' if entry.get('supported') else 'No'
    if not entry.get('supported') and entry.get('unsupported_reason'):
        supported = f"No. {entry['unsupported_reason']}"
    docs_url = entry.get('docs_url') or ''
    docs_link = f"[allauth docs]({docs_url})" if docs_url else '-'
    return (
        f"| {_icon_cell(entry.get('icon') or {})} {entry.get('name')} "
        f"| `{entry.get('docs_slug')}` "
        f"| {entry.get('protocol') or '-'} "
        f"| {_console_links(entry.get('console_url') or [])} "
        f"| {docs_link} "
        f"| {_extra_settings(entry)} "
        f"| {supported} |"
    )


CALLBACK_SECTION = [
    '## IdP callback URL (Shellui flow)',
    '',
    'Register **one** authorization callback URL on each IdP application. Point it at **identity-service**, not your Shellui shell. Do not add a query string.',
    '',
    '| Environment | Callback URL |',
    '| ----------- | ------------ |',
    '| Local | `http://localhost:8000/api/v1/oauth/callback` |',
    '| Production | `https://<identity-host>/api/v1/oauth/callback` |',
    '',
    'django-allauth\'s default pattern is `/accounts/<provider>/login/callback/` when you mount stock allauth URLs. identity-service does **not** expose that path for the Shellui authorize flow (`GET /api/v1/authorize` → `GET /api/v1/oauth/callback`). If an allauth provider page lists a different callback path, treat it as documentation for vanilla allauth only. Shellui always uses the table above.',
    '',
]


def main() -> int:
    catalog = json.loads(CATALOG_PATH.read_text(encoding='utf-8'))
    providers = catalog.get('providers') or []
    by_tier: dict[str, list] = {key: [] for key in TIER_HEADINGS}
    for entry in providers:
        tier = entry.get('tier') or 'other'
        by_tier.setdefault(tier, []).append(entry)
    for tier_entries in by_tier.values():
        tier_entries.sort(key=lambda item: str(item.get('name') or '').lower())

    lines = [
        '# OAuth providers',
        '',
        'identity-service ships a catalog of django-allauth social providers for Shellui admin setup.',
        'See [OAuth login](oauth-login.md) for the full authorize flow.',
        '',
        f"Catalog version **{catalog.get('catalog_version')}** (django-allauth **{catalog.get('allauth_version')}**).",
        '',
        '> This page is generated from `apps/authapi/provider_catalog.json`. Run `uv run python tools/render_oauth_providers_doc.py` after catalog changes.',
        '',
        *CALLBACK_SECTION,
    ]
    for tier, heading in TIER_HEADINGS.items():
        entries = by_tier.get(tier) or []
        if not entries:
            continue
        lines.extend(
            [
                f'## {heading}',
                '',
                '| | Provider | Catalog id | Protocol | Developer console | allauth docs | Extra settings | Shellui supported |',
                '| --- | --- | --- | --- | --- | --- | --- | --- |',
            ]
        )
        for entry in entries:
            lines.append(render_provider_row(entry))
        lines.append('')

    OUT_PATH.write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')
    print(f'Wrote {OUT_PATH}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
