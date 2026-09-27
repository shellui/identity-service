"""Action email templates for the admin editor (filesystem JSON defaults vs stored rule templates)."""

from __future__ import annotations

from apps.actions.email_i18n import default_email_language, normalize_language_code
from apps.actions.email_template_defaults import (
    read_default_subject_source,
    resolve_default_document,
)
from apps.actions.registry import EventFieldDoc, get_event_type
from apps.companies.models import Company


def _sample_data_from_event(event_type: str) -> dict:
    try:
        event = get_event_type(event_type)
    except ValueError:
        return {}
    data: dict = {}
    for field in (*event.payload_fields, *event.email_context_fields):
        if isinstance(field, EventFieldDoc) and field.example is not None:
            # email_context_fields use bare names (e.g. magic_link_url) → data.*
            name = field.name.removeprefix('data.')
            data[name] = field.example
    return data


def sample_envelope(*, event_type: str, company: Company) -> dict:
    return {
        'id': '00000000-0000-4000-8000-000000000001',
        'type': event_type,
        'time': '2026-01-01T12:00:00+00:00',
        'company': {'id': company.pk, 'slug': company.slug, 'name': company.name},
        'data': _sample_data_from_event(event_type),
    }


def sample_email_context(*, event_type: str, company: Company) -> dict:
    """Send-path shape: ``{ envelope, data }`` with catalog example values."""
    envelope = sample_envelope(event_type=event_type, company=company)
    return {'envelope': envelope, 'data': envelope.get('data') or {}}


def effective_email_template(
    *,
    rule_config: dict,
    event_type: str,
    company: Company,
    language: str | None,
) -> dict:
    """
    Stored rule template for *language* (``source: override``, includes ``html``), or the
    filesystem JSON default (``source: filesystem``, ``document`` + raw ``subject``, no html).
    """
    lang = normalize_language_code(language) or default_email_language()
    templates = (rule_config or {}).get('email_templates') or {}
    override = templates.get(lang) if isinstance(templates, dict) else None
    if isinstance(override, dict) and override.get('html'):
        payload = {
            'language': lang,
            'source': 'override',
            'subject': (override.get('subject') or '').strip(),
            'html': override.get('html') or '',
        }
        doc = override.get('document')
        if isinstance(doc, dict):
            payload['document'] = doc
        return payload
    return default_event_email_template(event_type=event_type, language=lang)


def default_event_email_template(
    *,
    event_type: str,
    language: str | None,
) -> dict:
    """
    Filesystem defaults for admin create/edit: React Email ``document`` JSON and raw subject.

    HTML is not shipped on disk; the admin compiles it from ``document`` and stores it on the rule.

    Raises ``ValueError`` when ``event_type`` is not in the catalog.
    Raises ``TemplateDoesNotExist`` when no JSON default exists.
    """
    event = get_event_type(event_type)
    lang = normalize_language_code(language) or default_email_language()
    document, resolved_lang = resolve_default_document(
        event_type,
        preferred=lang,
        use_user_preference=True,
    )
    subject_source, _sub_lang = read_default_subject_source(
        event_type,
        preferred=lang,
        use_user_preference=True,
    )
    subject = (subject_source or event.email_subject_template or '').strip()
    return {
        'language': resolved_lang,
        'source': 'filesystem',
        'subject': subject,
        'document': document,
    }
