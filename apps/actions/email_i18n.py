"""Locale resolution and template paths for action notification emails."""

from __future__ import annotations

from django.conf import settings
from django.template import TemplateDoesNotExist
from django.template.loader import get_template

FALLBACK_LANGUAGE = 'en'


def normalize_language_code(raw: str | None) -> str:
    if not raw or not isinstance(raw, str):
        return ''
    token = raw.strip().lower().replace('_', '-').split('-')[0]
    return token if token.isalpha() and 1 < len(token) <= 8 else ''


def default_email_language() -> str:
    configured = getattr(settings, 'ACTIONS_EMAIL_DEFAULT_LANGUAGE', FALLBACK_LANGUAGE)
    if not isinstance(configured, str) or not configured.strip():
        return FALLBACK_LANGUAGE
    return normalize_language_code(configured) or FALLBACK_LANGUAGE


def language_candidates(*, preferred: str | None, use_user_preference: bool) -> list[str]:
    """Resolution order: user preference (when applicable) → deployment default → ``en``."""
    ordered: list[str] = []
    seen: set[str] = set()

    def add(code: str | None) -> None:
        normalized = normalize_language_code(code) if code else ''
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        ordered.append(normalized)

    if use_user_preference:
        add(preferred)
    add(default_email_language())
    add(FALLBACK_LANGUAGE)
    return ordered


def _body_template_name(event_type: str, language: str) -> str:
    return f'actions/emails/{language}/{event_type}.html'


def _legacy_body_template_name(event_type: str) -> str:
    return f'actions/emails/{event_type}.html'


def _subject_template_name(event_type: str, language: str) -> str:
    return f'actions/emails/{language}/subjects/{event_type}.txt'


def resolve_body_template(
    event_type: str,
    *,
    preferred: str | None,
    use_user_preference: bool,
) -> tuple[str, str]:
    """Return ``(template_name, resolved_language)`` for the HTML body."""
    for language in language_candidates(preferred=preferred, use_user_preference=use_user_preference):
        name = _body_template_name(event_type, language)
        try:
            get_template(name)
            return name, language
        except TemplateDoesNotExist:
            continue
    legacy = _legacy_body_template_name(event_type)
    try:
        get_template(legacy)
        return legacy, FALLBACK_LANGUAGE
    except TemplateDoesNotExist as exc:
        raise TemplateDoesNotExist(f'No action email template for event {event_type!r}') from exc


def resolve_subject_template_name(
    event_type: str,
    *,
    preferred: str | None,
    use_user_preference: bool,
) -> tuple[str | None, str]:
    """
    Return ``(template_name, resolved_language)`` for a locale subject file,
    or ``(None, language)`` when the catalog inline subject should be used.
    """
    for language in language_candidates(preferred=preferred, use_user_preference=use_user_preference):
        name = _subject_template_name(event_type, language)
        try:
            get_template(name)
            return name, language
        except TemplateDoesNotExist:
            continue
    return None, FALLBACK_LANGUAGE


def user_preferred_language_from_envelope(envelope: dict) -> str | None:
    data = envelope.get('data') or {}
    raw = data.get('language')
    if not raw:
        return None
    normalized = normalize_language_code(raw)
    return normalized or None
