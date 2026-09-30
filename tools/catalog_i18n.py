"""Normalize OAuth catalog console links and extra settings for i18n-friendly JSON."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

CONSOLE_LINK_KINDS: tuple[str, ...] = (
    'app_registration',
    'developer_console',
    'app_settings',
    'docs',
    'other',
)

CONSOLE_LINK_FORMS: tuple[str, ...] = (
    'link',
    'template',
)

_ARTIFACT_QUERY_KEYS = frozenset({'newapp'})

_PLACEHOLDER_BRACE = re.compile(r'\{\{([^}]+)\}\}')
_PLACEHOLDER_CURLY = re.compile(r'\{([a-zA-Z0-9_-]+)\}')


def clean_console_url(raw: str) -> str:
    url = (raw or '').strip()
    if not url:
        return url
    if ' (' in url and url.startswith('http'):
        url = url.split(' (', 1)[0].strip()
    parsed = urlparse(url)
    if parsed.query:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        cleaned_pairs = [(k, v) for k, v in pairs if not (k in _ARTIFACT_QUERY_KEYS and v == '')]
        query = urlencode(cleaned_pairs)
        parsed = parsed._replace(query=query)
        url = urlunparse(parsed)
    url = url.rstrip('?')
    return url


def _extract_placeholders(url: str) -> list[str]:
    found: set[str] = set()
    for match in _PLACEHOLDER_BRACE.finditer(url):
        found.add(match.group(1).strip())
    for match in _PLACEHOLDER_CURLY.finditer(url):
        found.add(match.group(1).strip())
    lowered = url.lower()
    if 'example.org' in lowered or 'nextcloud.example' in lowered:
        found.add('host')
    if 'your-tenant' in lowered or 'your.auth0domain' in lowered:
        found.add('tenant_host')
    if 'yourusername' in lowered or '{{yourusername}}' in url:
        found.add('username')
    return sorted(found)


def infer_console_link_kind(label: str, url: str) -> str:
    blob = f'{label} {url}'.lower()
    if '/doc' in blob or 'docs.' in url.lower() or 'documentation' in blob or 'follow the' in blob:
        return 'docs'
    if 'developer console' in blob or 'developer portal' in blob or 'console.cloud.google' in blob:
        return 'developer_console'
    if (
        'private key' in blob
        or 'keys tab' in blob
        or '/settings' in url.lower()
        or '/keys' in url.lower()
    ):
        return 'app_settings'
    if (
        'app registration' in blob
        or blob.startswith('register')
        or 'register your' in blob
        or '/oauth/register' in url.lower()
        or '/applications/create' in url.lower()
        or 'apps/oauth' in url.lower()
    ):
        return 'app_registration'
    if 'signup' in blob or 'manage-apps' in url.lower():
        return 'app_registration'
    return 'other'


def normalize_console_link(raw: dict) -> dict | None:
    if not isinstance(raw, dict):
        return None
    url = clean_console_url(str(raw.get('url') or raw.get('text') or '').strip())
    if not url.startswith(('http://', 'https://')):
        return None
    label = str(raw.get('label') or '').strip()
    kind = infer_console_link_kind(label, url)
    placeholders = _extract_placeholders(url)
    form = 'template' if placeholders else 'link'
    out: dict = {'kind': kind, 'url': url, 'form': form}
    if placeholders:
        out['placeholders'] = placeholders
    return out


def normalize_console_urls(raw_links: list | None) -> list[dict]:
    normalized: list[dict] = []
    for item in raw_links or []:
        link = normalize_console_link(item)
        if link is not None:
            normalized.append(link)
    return normalized


def normalize_extra_setting_field(raw: dict) -> dict:
    return {
        'name': str(raw['name']),
        'type': str(raw.get('type') or 'string'),
        'required': bool(raw.get('required')),
        'secret': bool(raw.get('secret')),
    }


def normalize_extra_settings_schema(raw_schema: list | None) -> list[dict]:
    out: list[dict] = []
    for item in raw_schema or []:
        if isinstance(item, dict) and item.get('name'):
            out.append(normalize_extra_setting_field(item))
    return out
