"""Transactional magic-link sign-in email (not routed through Action rules)."""

from __future__ import annotations

import html2text
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template

from apps.authapi.magic_link import magic_link_url_for_request
from apps.authapi.template_substitute import substitute_action_email_template
from apps.companies.models import Company


def _resolve_language(*, user, payload_language: str | None) -> str:
    if payload_language and str(payload_language).strip():
        lang = str(payload_language).strip().lower().split('-')[0]
        if lang in {'en', 'fr'}:
            return lang
    if user is not None:
        pref = getattr(user, 'preference', None)
        if pref is not None:
            lang = (getattr(pref, 'language', None) or '').strip().lower().split('-')[0]
            if lang in {'en', 'fr'}:
                return lang
    default = (getattr(settings, 'MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE', None) or 'en').strip().lower()
    return default if default in {'en', 'fr'} else 'en'


def _html_to_plain(html: str) -> str:
    converter = html2text.HTML2Text()
    converter.body_width = 0
    converter.ignore_images = True
    converter.unicode_snob = True
    return converter.handle(html or '').strip()


def send_magic_link_email(*, row, company: Company, user=None, language: str | None = None) -> None:
    """
    Send the passwordless sign-in email directly (EN/FR templates on disk).

    Does not include secrets in logs; the link is built from the stored token row.
    """
    magic_link_url = magic_link_url_for_request(row.pk)
    if not magic_link_url:
        return

    lang = _resolve_language(user=user, payload_language=language)
    subject_tpl = get_template(f'authapi/magic_link/subjects/{lang}.txt').template.source
    html_tpl = get_template(f'authapi/magic_link/{lang}.html').template.source
    context = {
        'envelope': {
            'company': {'id': company.pk, 'slug': company.slug, 'name': company.name},
        },
        'data': {
            'email': row.email,
            'magic_link_url': magic_link_url,
        },
    }
    subject = substitute_action_email_template(subject_tpl, context, mode='plain').strip()
    html_body = substitute_action_email_template(html_tpl, context, mode='html')
    text_body = _html_to_plain(html_body)

    message = EmailMultiAlternatives(
        subject=subject,
        body=text_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[row.email],
    )
    message.attach_alternative(html_body, 'text/html')
    message.send(fail_silently=False)
