from __future__ import annotations

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import engines, render_to_string

from apps.actions.html_plain import html_to_plain_text
from apps.actions.registry import get_event_type


def _resolve_recipients(config: dict, envelope: dict) -> list[str]:
    recipients: list[str] = []
    for raw in config.get('recipients') or []:
        if isinstance(raw, str) and raw.strip():
            recipients.append(raw.strip())
    event = get_event_type(envelope['type'])
    if config.get('include_payload_email') and event.email_payload_email_field:
        payload_email = (envelope.get('data') or {}).get(event.email_payload_email_field)
        if isinstance(payload_email, str) and payload_email.strip():
            recipients.append(payload_email.strip())
    # De-dupe while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for addr in recipients:
        key = addr.lower()
        if key not in seen:
            seen.add(key)
            unique.append(addr)
    if not unique:
        raise ValueError('Email action has no recipients configured.')
    return unique


_SUBJECT_TEMPLATE_CACHE: dict[str, object] = {}


def _subject_template(subject_template: str):
    cached = _SUBJECT_TEMPLATE_CACHE.get(subject_template)
    if cached is not None:
        return cached
    engine = engines['django']
    compiled = engine.from_string(subject_template)
    _SUBJECT_TEMPLATE_CACHE[subject_template] = compiled
    return compiled


def _render_subject(event_type: str, envelope: dict) -> str:
    event = get_event_type(event_type)
    template = _subject_template(event.email_subject_template)
    return template.render(
        {
            'data': envelope.get('data') or {},
            'envelope': envelope,
        }
    ).strip()


def deliver_email_action(*, config: dict, envelope: dict) -> None:
    event_type = envelope['type']
    recipients = _resolve_recipients(config, envelope)
    subject = _render_subject(event_type, envelope)
    html_body = render_to_string(
        f'actions/emails/{event_type}.html',
        {'envelope': envelope, 'data': envelope.get('data') or {}},
    )
    text_body = html_to_plain_text(html_body)
    message = EmailMultiAlternatives(
        subject=subject,
        body=text_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=recipients,
    )
    message.attach_alternative(html_body, 'text/html')
    message.send(fail_silently=False)
