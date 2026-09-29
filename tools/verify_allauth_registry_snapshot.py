#!/usr/bin/env python3
"""Fail CI when installed allauth registry diverges from the committed provider source snapshot."""

from __future__ import annotations

import importlib.metadata
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
os.environ.setdefault('SECRET_KEY', 'registry-verify-not-for-production')
os.environ.setdefault('DEBUG', 'true')

import django

django.setup()

SOURCE_PATH = ROOT / 'tools' / 'data' / 'allauth_providers_source.json'
METADATA_PATH = ROOT / 'tools' / 'data' / 'allauth_providers_metadata.json'


def _registry_provider_ids() -> set[str]:
    from allauth.socialaccount.providers import registry

    ids: set[str] = set()
    for cls in registry.get_class_list():
        ids.add(str(getattr(cls, 'id', cls)))
    return ids


def main() -> int:
    installed_version = importlib.metadata.version('django-allauth')
    if not SOURCE_PATH.is_file():
        print(f'Missing {SOURCE_PATH}', file=sys.stderr)
        return 1
    source_entries = json.loads(SOURCE_PATH.read_text(encoding='utf-8'))
    if not isinstance(source_entries, list):
        print('allauth_providers_source.json must be a list.', file=sys.stderr)
        return 1
    source_ids = {str(item.get('id') or item.get('docs_slug') or '').strip() for item in source_entries}
    source_ids.discard('')
    registry_ids = _registry_provider_ids()
    missing_in_source = sorted(registry_ids - source_ids)
    if missing_in_source:
        print('Providers in allauth registry but missing from source snapshot:', missing_in_source, file=sys.stderr)
        return 1
    if METADATA_PATH.is_file():
        meta = json.loads(METADATA_PATH.read_text(encoding='utf-8'))
        if isinstance(meta, dict) and meta.get('allauth_version'):
            expected = str(meta['allauth_version'])
            if expected != installed_version:
                print(
                    f'Metadata allauth_version {expected!r} != installed {installed_version!r}',
                    file=sys.stderr,
                )
                return 1
    print(f'Registry snapshot OK ({len(registry_ids)} providers, allauth {installed_version})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
