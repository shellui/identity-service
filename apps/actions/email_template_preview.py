"""Effective action email templates for admin preview (filesystem defaults vs rule overrides)."""

from __future__ import annotations

from apps.actions.email_i18n import (
    default_email_language,
    normalize_language_code,
    resolve_body_template,
    resolve_subject_template_name,
)
from apps.actions.email_template_defaults import (
    read_default_document,
    read_default_html_source,
    read_default_subject_source,
)
from apps.actions.email_template_substitute import substitute_action_email_template
from apps.actions.registry import EventFieldDoc, get_event_type
from apps.companies.models import Company


def _sample_data_from_event(event_type: str) -> dict:
    try:
        event = get_event_type(event_type)
    except ValueError:
        return {}
    data: dict = {}
    for field in event.payload_fields:
        if isinstance(field, EventFieldDoc) and field.example is not None:
            data[field.name] = field.example
    return data


def sample_envelope(*, event_type: str, company: Company) -> dict:
    return {
        'id': '00000000-0000-4000-8000-000000000001',
        'type': event_type,
        'time': '2026-01-01T12:00:00+00:00',
        'company': {'id': company.pk, 'slug': company.slug, 'name': company.name},
        'data': _sample_data_from_event(event_type),
    }


def effective_email_template(
    *,
    rule_config: dict,
    event_type: str,
    company: Company,
    language: str | None,
    use_user_preference: bool = False,
) -> dict:
    """
    Return ``subject``, ``html``, optional ``document``, ``language``, and ``source``.
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

    envelope = sample_envelope(event_type=event_type, company=company)
    context = {'envelope': envelope, 'data': envelope.get('data') or {}}
    template_name, resolved_lang = resolve_body_template(
        event_type,
        preferred=lang,
        use_user_preference=use_user_preference,
    )
    html = substitute_action_email_template(read_default_html_source(template_name), context)
    subject_source, _sub_lang = read_default_subject_source(
        event_type,
        preferred=lang,
        use_user_preference=use_user_preference,
    )
    if subject_source:
        subject = substitute_action_email_template(subject_source, context).strip()
    else:
        event = get_event_type(event_type)
        subject = substitute_action_email_template(event.email_subject_template, context).strip()
    payload = {
        'language': resolved_lang,
        'source': 'filesystem',
        'subject': subject,
        'html': html,
    }
    document = read_default_document(template_name)
    if document is not None:
        payload['document'] = document
    return payload


def default_event_email_template(
    *,
    event_type: str,
    language: str | None,
) -> dict:
    """
    Raw filesystem defaults for admin create/edit (unrendered HTML + React Email document JSON).

    Raises ``ValueError`` when ``event_type`` is not in the catalog.
    Raises ``TemplateDoesNotExist`` when no body template file exists.
    """
    get_event_type(event_type)
    lang = normalize_language_code(language) or default_email_language()
    template_name, resolved_lang = resolve_body_template(
        event_type,
        preferred=lang,
        use_user_preference=True,
    )
    html = read_default_html_source(template_name)
    subject_source, _sub_lang = read_default_subject_source(
        event_type,
        preferred=lang,
        use_user_preference=True,
    )
    if subject_source:
        subject = subject_source.strip()
    else:
        event = get_event_type(event_type)
        subject = (event.email_subject_template or '').strip()
    payload = {
        'language': resolved_lang,
        'source': 'filesystem',
        'subject': subject,
        'html': html,
        'body_html': html,
    }
    document = read_default_document(template_name)
    if document is not None:
        payload['document'] = document
    return payload
