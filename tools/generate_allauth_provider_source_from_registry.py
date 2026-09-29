#!/usr/bin/env python3
"""Merge django-allauth registry entries with curated provider metadata."""

from __future__ import annotations

import importlib.metadata
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
METADATA_PATH = ROOT / 'tools' / 'data' / 'allauth_providers_metadata.json'
OUT_PATH = ROOT / 'tools' / 'data' / 'allauth_providers_source.json'


def _django_setup() -> None:
    import os

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    import django

    django.setup()


def main() -> int:
    _django_setup()
    from allauth.socialaccount.providers import registry

    installed_version = importlib.metadata.version('django-allauth')
    metadata_by_slug: dict[str, dict] = {}
    if METADATA_PATH.is_file():
        for row in json.loads(METADATA_PATH.read_text(encoding='utf-8')):
            if isinstance(row, dict) and row.get('docs_slug'):
                metadata_by_slug[str(row['docs_slug'])] = row
    elif (ROOT / 'tools' / 'data' / 'allauth_providers_source.json').is_file():
        for row in json.loads(
            (ROOT / 'tools' / 'data' / 'allauth_providers_source.json').read_text(encoding='utf-8')
        ):
            if isinstance(row, dict) and row.get('docs_slug'):
                metadata_by_slug[str(row['docs_slug'])] = row

    merged: list[dict] = []
    seen: set[str] = set()
    for provider in registry.get_list():
        slug = provider.id
        if slug in seen:
            continue
        seen.add(slug)
        app_path = f'allauth.socialaccount.providers.{slug}'
        meta = metadata_by_slug.get(slug, {})
        merged.append(
            {
                'id': slug,
                'provider_id': meta.get('provider_id'),
                'docs_slug': meta.get('docs_slug') or slug,
                'app': meta.get('app') or app_path,
                'name': meta.get('name') or getattr(provider, 'name', slug),
                'docs_url': meta.get('docs_url') or '',
                'console_url': meta.get('console_url') or [],
                'callback_path': meta.get('callback_path') or meta.get('expected_callback_path'),
                'expected_callback_path': meta.get('expected_callback_path') or meta.get('callback_path'),
                'extra_settings': meta.get('extra_settings') or [],
                'protocol': meta.get('protocol') or 'OAuth2',
                'protocol_detail': meta.get('protocol_detail'),
                'tier': meta.get('tier') or 'other',
                'popular': bool(meta.get('popular')),
                'legacy': bool(meta.get('legacy')),
                'replaced_by': meta.get('replaced_by'),
                'icon': meta.get('icon') or {
                    'source': 'fallback',
                    'slug': 'log-in',
                    'hex': '64748B',
                    'title': slug,
                },
                'notes': meta.get('notes') or '',
                'caveats': meta.get('caveats') or [],
            }
        )

    merged.sort(key=lambda item: item['docs_slug'])
    OUT_PATH.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f'Wrote {len(merged)} registry providers to {OUT_PATH} (django-allauth {installed_version})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
