"""Transactional magic-link sign-in email (static repo templates only)."""

from __future__ import annotations

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string

from apps.authapi.magic_link import magic_link_url_for_request
from apps.companies.models import Company

_SUPPORTED = frozenset({'en', 'fr'})


def _resolve_language(*, user, payload_language: str | None) -> str:
    if payload_language and str(payload_language).strip():
        lang = str(payload_language).strip().lower().split('-')[0]
        if lang in _SUPPORTED:
            return lang
    if user is not None:
        pref = getattr(user, 'preference', None)
        if pref is not None:
            lang = (getattr(pref, 'language', None) or '').strip().lower().split('-')[0]
            if lang in _SUPPORTED:
                return lang
    default = (getattr(settings, 'MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE', None) or 'en').strip().lower()
    return default if default in _SUPPORTED else 'en'


def _render(template_name: str, context: dict, *, language: str) -> str:
    for lang in (language, 'en'):
        path = f'authapi/magic_link/{template_name.format(lang=lang)}'
        try:
            return render_to_string(path, context).strip()
        except TemplateDoesNotExist:
            continue
    raise TemplateDoesNotExist(template_name)


def send_magic_link_email(
    *,
    row,
    company: Company,
    user=None,
    language: str | None = None,
    raw_token: str,
) -> None:
    magic_link_url = magic_link_url_for_request(row.pk, raw_token=raw_token)
    if not magic_link_url:
        return

    lang = _resolve_language(user=user, payload_language=language)
    context = {
        'company_name': company.name,
        'email': row.email,
        'magic_link_url': magic_link_url,
    }
    subject = _render('subjects/{lang}.txt', context, language=lang)
    html_body = _render('{lang}.html', context, language=lang)
    text_body = _render('{lang}.txt', context, language=lang)

    message = EmailMultiAlternatives(
        subject=subject,
        body=text_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[row.email],
    )
    message.attach_alternative(html_body, 'text/html')
    message.send(fail_silently=False)
