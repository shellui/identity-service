from __future__ import annotations

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import engines, get_template, render_to_string

from apps.actions.email_i18n import (
    resolve_body_template,
    resolve_subject_template_name,
    user_preferred_language_from_envelope,
)
from apps.actions.html_plain import html_to_plain_text
from apps.actions.registry import get_event_type


def _split_recipient_batches(config: dict, envelope: dict) -> list[tuple[list[str], bool]]:
    """
    Return delivery batches as ``(recipients, use_user_preference)``.

    Fixed ops addresses use deployment/company default language; payload email uses the
    subject user's preferred language from ``data.language`` when present.
    """
    event = get_event_type(envelope['type'])
    fixed: list[str] = []
    for raw in config.get('recipients') or []:
        if isinstance(raw, str) and raw.strip():
            fixed.append(raw.strip())

    payload_email: str | None = None
    if config.get('include_payload_email') and event.email_payload_email_field:
        payload_raw = (envelope.get('data') or {}).get(event.email_payload_email_field)
        if isinstance(payload_raw, str) and payload_raw.strip():
            payload_email = payload_raw.strip()

    seen: set[str] = set()
    unique_fixed: list[str] = []
    for addr in fixed:
        key = addr.lower()
        if key not in seen:
            seen.add(key)
            unique_fixed.append(addr)

    batches: list[tuple[list[str], bool]] = []
    if unique_fixed:
        batches.append((unique_fixed, False))
    if payload_email and payload_email.lower() not in seen:
        batches.append(([payload_email], True))
    elif payload_email and not unique_fixed:
        batches.append(([payload_email], True))

    if not batches:
        raise ValueError('Email action has no recipients configured.')
    return batches


_SUBJECT_TEMPLATE_CACHE: dict[str, object] = {}


def _subject_template(subject_template: str):
    cached = _SUBJECT_TEMPLATE_CACHE.get(subject_template)
    if cached is not None:
        return cached
    engine = engines['django']
    compiled = engine.from_string(subject_template)
    _SUBJECT_TEMPLATE_CACHE[subject_template] = compiled
    return compiled


def _render_subject(
    event_type: str,
    envelope: dict,
    *,
    use_user_preference: bool,
) -> str:
    context = {
        'data': envelope.get('data') or {},
        'envelope': envelope,
    }
    preferred = user_preferred_language_from_envelope(envelope)
    subject_template_name, _resolved = resolve_subject_template_name(
        event_type,
        preferred=preferred,
        use_user_preference=use_user_preference,
    )
    if subject_template_name:
        return get_template(subject_template_name).render(context).strip()

    event = get_event_type(event_type)
    template = _subject_template(event.email_subject_template)
    return template.render(context).strip()


def _send_html_email(*, recipients: list[str], subject: str, html_body: str) -> None:
    text_body = html_to_plain_text(html_body)
    message = EmailMultiAlternatives(
        subject=subject,
        body=text_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=recipients,
    )
    message.attach_alternative(html_body, 'text/html')
    message.send(fail_silently=False)


def _email_action_data(envelope: dict) -> dict:
    data = dict(envelope.get('data') or {})
    if envelope.get('type') == 'identity.auth.magic_link.requested':
        from apps.authapi.magic_link import magic_link_url_for_request

        url = magic_link_url_for_request(data.get('request_id'))
        if url:
            data = {**data, 'magic_link_url': url}
    return data


def deliver_email_action(*, config: dict, envelope: dict) -> None:
    event_type = envelope['type']
    preferred = user_preferred_language_from_envelope(envelope)
    context = {'envelope': envelope, 'data': _email_action_data(envelope)}

    for recipients, use_user_preference in _split_recipient_batches(config, envelope):
        subject = _render_subject(
            event_type,
            envelope,
            use_user_preference=use_user_preference,
        )
        template_name, _lang = resolve_body_template(
            event_type,
            preferred=preferred,
            use_user_preference=use_user_preference,
        )
        html_body = render_to_string(template_name, context)
        _send_html_email(recipients=recipients, subject=subject, html_body=html_body)
