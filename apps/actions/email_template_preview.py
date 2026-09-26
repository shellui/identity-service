"""Effective action email templates for admin preview (filesystem defaults vs rule overrides)."""

from __future__ import annotations

from django.template.loader import engines, get_template, render_to_string

from apps.actions.email_i18n import (
    default_email_language,
    normalize_language_code,
    resolve_body_template,
    resolve_subject_template_name,
)
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
    Return ``subject``, ``html``, ``language``, and ``source`` (``override`` or ``filesystem``).
    """
    lang = normalize_language_code(language) or default_email_language()
    templates = (rule_config or {}).get('email_templates') or {}
    override = templates.get(lang) if isinstance(templates, dict) else None
    if isinstance(override, dict) and override.get('html'):
        return {
            'language': lang,
            'source': 'override',
            'subject': (override.get('subject') or '').strip(),
            'html': override.get('html') or '',
        }

    envelope = sample_envelope(event_type=event_type, company=company)
    context = {'envelope': envelope, 'data': envelope.get('data') or {}}
    template_name, resolved_lang = resolve_body_template(
        event_type,
        preferred=lang,
        use_user_preference=use_user_preference,
    )
    html = render_to_string(template_name, context)
    subject_template_name, _sub_lang = resolve_subject_template_name(
        event_type,
        preferred=lang,
        use_user_preference=use_user_preference,
    )
    if subject_template_name:
        subject = get_template(subject_template_name).render(context).strip()
    else:
        event = get_event_type(event_type)
        engine = engines['django']
        subject = engine.from_string(event.email_subject_template).render(context).strip()
    return {
        'language': resolved_lang,
        'source': 'filesystem',
        'subject': subject,
        'html': html,
    }
