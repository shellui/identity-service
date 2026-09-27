"""Load filesystem default action email documents (React Email JSON) and subjects.

Defaults ship as JSON only. HTML is compiled in the admin browser and stored on the
rule; the send path never reads HTML from disk.
"""

from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.template import TemplateDoesNotExist


def _templates_root() -> Path:
    return Path(settings.BASE_DIR) / 'apps/actions/templates/actions/emails'


def _document_path(event_type: str, language: str) -> Path:
    return _templates_root() / language / f'{event_type}.json'


def _subject_path(event_type: str, language: str) -> Path:
    return _templates_root() / language / 'subjects' / f'{event_type}.txt'


def resolve_default_document(
    event_type: str,
    *,
    preferred: str | None,
    use_user_preference: bool,
) -> tuple[dict, str]:
    """Return ``(document, resolved_language)`` for the first locale with a JSON default."""
    from apps.actions.email_i18n import language_candidates

    for language in language_candidates(preferred=preferred, use_user_preference=use_user_preference):
        path = _document_path(event_type, language)
        if not path.is_file():
            continue
        with path.open(encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data, language
    raise TemplateDoesNotExist(f'No default action email document for event {event_type!r}')


def read_default_subject_source(
    event_type: str,
    *,
    preferred: str | None,
    use_user_preference: bool,
) -> tuple[str | None, str]:
    from apps.actions.email_i18n import FALLBACK_LANGUAGE, language_candidates

    for language in language_candidates(preferred=preferred, use_user_preference=use_user_preference):
        path = _subject_path(event_type, language)
        if path.is_file():
            return path.read_text(encoding='utf-8'), language
    return None, FALLBACK_LANGUAGE
