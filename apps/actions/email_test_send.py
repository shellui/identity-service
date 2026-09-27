"""Send a one-off action email preview to the authenticated admin user."""

from __future__ import annotations

from apps.actions.email_i18n import default_email_language, normalize_language_code
from apps.actions.email_template_preview import sample_email_context
from apps.actions.email_template_substitute import substitute_action_email_template
from apps.actions.handlers.email import _send_html_email
from apps.actions.registry import get_event_type
from apps.companies.models import Company


def send_action_email_test_to_self(
    *,
    user_email: str,
    event_type: str,
    company: Company,
    language: str | None,
    subject: str,
    html: str,
) -> dict[str, str]:
    """
    Substitute sample context into *subject*/*html* and mail only *user_email*.

    Does not use rule recipients or the action outbox.
    """
    to = (user_email or '').strip()
    if not to:
        raise ValueError('Your account has no email address.')

    get_event_type(event_type)  # raises ValueError if unknown
    html_raw = (html or '').strip()
    if not html_raw:
        raise ValueError('HTML body is required to send a test email.')

    lang = normalize_language_code(language) or default_email_language()
    context = sample_email_context(event_type=event_type, company=company)
    html_body = substitute_action_email_template(html_raw, context, mode='html')
    subj = substitute_action_email_template(subject or '', context, mode='plain').strip()
    if not subj:
        subj = f'Test · {event_type}'
    if not subj.lower().startswith('[test]'):
        subj = f'[Test] {subj}'

    _send_html_email(recipients=[to], subject=subj, html_body=html_body)
    return {'sent_to': to, 'language': lang, 'subject': subj}
