"""Transactional company invitation email (static repo templates, EN and FR)."""

from __future__ import annotations

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string

from apps.companies.models import Company


def _render(template_name: str, context: dict, *, language: str) -> str:
    for lang in (language, 'en'):
        path = f'authapi/invitation/{template_name.format(lang=lang)}'
        try:
            return render_to_string(path, context).strip()
        except TemplateDoesNotExist:
            continue
    raise TemplateDoesNotExist(template_name)


def send_invitation_email(
    *,
    company: Company,
    email: str,
    inviter_name: str,
    app_url: str | None,
    language: str,
) -> None:
    context = {
        'company_name': company.name,
        'inviter_name': inviter_name,
        'email': email,
        'app_url': app_url,
    }
    message = EmailMultiAlternatives(
        subject=_render('subjects/{lang}.txt', context, language=language),
        body=_render('{lang}.txt', context, language=language),
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[email],
    )
    message.attach_alternative(_render('{lang}.html', context, language=language), 'text/html')
    message.send(fail_silently=False)
