from __future__ import annotations

from django.conf import settings
from django.core.mail import EmailMultiAlternatives

from apps.actions.email_i18n import (
    render_action_email_body,
    render_action_email_subject,
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
        subject = render_action_email_subject(
            event_type,
            preferred=preferred,
            use_user_preference=use_user_preference,
            rule_config=config,
            context=context,
        )
        html_body, _lang = render_action_email_body(
            event_type,
            preferred=preferred,
            use_user_preference=use_user_preference,
            rule_config=config,
            context=context,
        )
        _send_html_email(recipients=recipients, subject=subject, html_body=html_body)
