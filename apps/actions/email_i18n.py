"""Locale resolution and rendering for action notification emails."""

from __future__ import annotations

from django.conf import settings

from apps.actions.email_template_substitute import substitute_action_email_template

FALLBACK_LANGUAGE = 'en'

MISSING_COMPILED_TEMPLATE_MESSAGE = (
    'Email rule has no compiled HTML template. Open the rule in the Shellui admin '
    '(Actions → Rules) and save it to compile the template.'
)


class MissingCompiledEmailTemplateError(ValueError):
    """Raised when an email rule has no stored ``email_templates[*].html`` to send."""

    def __init__(self, message: str = MISSING_COMPILED_TEMPLATE_MESSAGE):
        super().__init__(message)


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


def user_preferred_language_from_envelope(envelope: dict) -> str | None:
    data = envelope.get('data') or {}
    raw = data.get('language')
    if not raw:
        return None
    normalized = normalize_language_code(raw)
    return normalized or None


def _compiled_rule_templates(rule_config: dict | None) -> dict[str, dict]:
    templates = (rule_config or {}).get('email_templates') or {}
    if not isinstance(templates, dict):
        return {}
    return {
        lang: entry
        for lang, entry in templates.items()
        if isinstance(lang, str) and isinstance(entry, dict) and entry.get('html')
    }


def select_rule_email_template(
    rule_config: dict | None,
    *,
    preferred: str | None,
    use_user_preference: bool,
) -> tuple[dict, str]:
    """
    Pick the stored compiled template for delivery.

    Order: user preference (when applicable) → deployment default → ``en`` → any
    other stored locale. Raises ``MissingCompiledEmailTemplateError`` when none exist.
    """
    compiled = _compiled_rule_templates(rule_config)
    for language in language_candidates(preferred=preferred, use_user_preference=use_user_preference):
        if language in compiled:
            return compiled[language], language
    for language in sorted(compiled):
        return compiled[language], language
    raise MissingCompiledEmailTemplateError()


def render_action_email(
    event_type: str,
    *,
    preferred: str | None,
    use_user_preference: bool,
    rule_config: dict | None,
    context: dict,
) -> tuple[str, str, str]:
    """Return ``(subject, html_body, resolved_language)`` from the rule's compiled template."""
    from apps.actions.registry import get_event_type

    entry, language = select_rule_email_template(
        rule_config,
        preferred=preferred,
        use_user_preference=use_user_preference,
    )
    html = substitute_action_email_template(entry['html'], context, mode='html')
    subject_source = (entry.get('subject') or '').strip() or get_event_type(event_type).email_subject_template
    subject = substitute_action_email_template(subject_source, context, mode='plain').strip()
    return subject, html, language
