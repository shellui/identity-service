"""Load filesystem default action email HTML, JSON documents, and subjects."""

from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.template import TemplateDoesNotExist

_FALLBACK_LANGUAGE = 'en'


def _templates_root() -> Path:
    return Path(settings.BASE_DIR) / 'apps/actions/templates/actions/emails'


def _body_template_name(event_type: str, language: str) -> str:
    return f'actions/emails/{language}/{event_type}.html'


def _legacy_body_template_name(event_type: str) -> str:
    return f'actions/emails/{event_type}.html'


def _subject_template_name(event_type: str, language: str) -> str:
    return f'actions/emails/{language}/subjects/{event_type}.txt'


def _json_path_for_html_template(template_name: str) -> Path:
    rel = template_name.replace('actions/emails/', '')
    if rel.endswith('.html'):
        rel = rel[: -len('.html')] + '.json'
    return _templates_root() / rel


def read_default_html_source(template_name: str) -> str:
    rel = template_name.replace('actions/emails/', '')
    path = _templates_root() / rel
    if not path.is_file():
        raise TemplateDoesNotExist(template_name)
    return path.read_text(encoding='utf-8')


def read_default_document(template_name: str) -> dict | None:
    path = _json_path_for_html_template(template_name)
    if not path.is_file():
        return None
    with path.open(encoding='utf-8') as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else None


def resolve_default_body_template_name(
    event_type: str,
    *,
    preferred: str | None,
    use_user_preference: bool,
) -> tuple[str, str]:
    from apps.actions.email_i18n import language_candidates

    for language in language_candidates(preferred=preferred, use_user_preference=use_user_preference):
        name = _body_template_name(event_type, language)
        path = _templates_root() / f'{language}/{event_type}.html'
        if path.is_file():
            return name, language
    legacy = _legacy_body_template_name(event_type)
    legacy_path = _templates_root() / f'{event_type}.html'
    if legacy_path.is_file():
        return legacy, _FALLBACK_LANGUAGE
    raise TemplateDoesNotExist(f'No action email template for event {event_type!r}')


def read_default_subject_source(
    event_type: str,
    *,
    preferred: str | None,
    use_user_preference: bool,
) -> tuple[str | None, str]:
    from apps.actions.email_i18n import language_candidates

    for language in language_candidates(preferred=preferred, use_user_preference=use_user_preference):
        name = _subject_template_name(event_type, language)
        path = _templates_root() / f'{language}/subjects/{event_type}.txt'
        if path.is_file():
            return path.read_text(encoding='utf-8'), language
    return None, _FALLBACK_LANGUAGE
