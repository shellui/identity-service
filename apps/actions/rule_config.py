"""Build and validate ActionRule.config for admin UI and REST API."""

from __future__ import annotations

import re

from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from apps.actions.email_template_substitute import assert_no_django_template_tags
from apps.actions.models import ActionRule
from apps.actions.registry import get_event_type

_REMOTE_STYLESHEET_RE = re.compile(
    r'<link\b[^>]*\brel\s*=\s*["\']?stylesheet["\']?[^>]*\bhref\s*=\s*["\']https?://',
    re.IGNORECASE,
)
_EXTERNAL_SCRIPT_RE = re.compile(r'<script\b[^>]*\bsrc\s*=\s*["\']https?://', re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r'<script\b', re.IGNORECASE)


def validate_email_template_html(html: str) -> None:
    if _INLINE_SCRIPT_RE.search(html):
        raise ValidationError('HTML must not include script tags.')
    if _EXTERNAL_SCRIPT_RE.search(html):
        raise ValidationError('HTML must not load external scripts.')
    if _REMOTE_STYLESHEET_RE.search(html):
        raise ValidationError('HTML must not load remote stylesheets.')


def normalize_email_templates(raw: object | None) -> dict[str, dict[str, object]]:
    if not raw or not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, object]] = {}
    for lang_key, entry in raw.items():
        if not isinstance(lang_key, str) or not isinstance(entry, dict):
            continue
        lang = lang_key.strip().lower().split('-')[0]
        if not lang:
            continue
        subject = entry.get('subject')
        html = entry.get('html')
        document = entry.get('document')
        subject_s = subject.strip() if isinstance(subject, str) else ''
        html_s = html if isinstance(html, str) else ''
        if not subject_s and not html_s and document is None:
            continue
        if html_s and not subject_s:
            raise ValidationError(f'email_templates[{lang_key}]: subject is required when html is set.')
        if html_s:
            validate_email_template_html(html_s)
            assert_no_django_template_tags(html_s, field_label=f'email_templates[{lang_key}].html')
        if subject_s:
            assert_no_django_template_tags(subject_s, field_label=f'email_templates[{lang_key}].subject')
        stored: dict[str, object] = {'subject': subject_s, 'html': html_s}
        if isinstance(document, dict) and document.get('type') == 'doc':
            stored['document'] = document
        preview = entry.get('preview')
        if isinstance(preview, str) and preview.strip():
            stored['preview'] = preview.strip()
        theme_id = entry.get('theme_id')
        if isinstance(theme_id, str) and theme_id.strip():
            stored['theme_id'] = theme_id.strip()
        out[lang] = stored
    return out


def _parse_recipients(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.split(',') if p.strip()]
    elif isinstance(raw, list):
        parts = [str(p).strip() for p in raw if str(p).strip()]
    else:
        raise ValidationError('recipients must be a list of email addresses or a comma-separated string.')
    for addr in parts:
        validate_email(addr)
    return parts


def build_email_config(
    *,
    existing: dict,
    recipients: object | None = None,
    include_payload_email: bool | None = None,
    email_templates: object | None = None,
    event_type: str,
    partial: bool,
) -> dict:
    cfg = dict(existing or {})
    if recipients is not None or not partial:
        cfg['recipients'] = _parse_recipients(recipients if recipients is not None else cfg.get('recipients'))
    if include_payload_email is not None or not partial:
        cfg['include_payload_email'] = bool(
            include_payload_email
            if include_payload_email is not None
            else cfg.get('include_payload_email')
        )
    if email_templates is not None:
        cfg['email_templates'] = normalize_email_templates(email_templates)
    elif not partial and 'email_templates' not in cfg:
        cfg.setdefault('email_templates', {})

    payload_field = None
    try:
        payload_field = get_event_type(event_type).email_payload_email_field
    except ValueError:
        pass
    recips = cfg.get('recipients') or []
    inc = bool(cfg.get('include_payload_email'))
    if not recips and not (inc and payload_field):
        raise ValidationError(
            'Add at least one recipient, or enable include_payload_email for an event type that provides an email.'
        )
    return cfg


def build_webhook_config(
    *,
    existing: dict,
    url: str | None = None,
    secret: str | None = None,
    authorization_header: str | None = None,
    allow_private_urls: bool | None = None,
    is_superuser: bool,
    partial: bool,
) -> dict:
    cfg = dict(existing or {})
    if url is not None or not partial:
        cfg['url'] = (url if url is not None else cfg.get('url') or '').strip()
    if not cfg.get('url'):
        raise ValidationError('Webhook url is required.')

    if secret is not None:
        secret_s = (secret or '').strip()
        if secret_s:
            cfg['secret'] = secret_s
        elif existing.get('secret'):
            cfg['secret'] = existing['secret']
        elif not partial:
            raise ValidationError('Webhook signing secret is required for new webhook rules.')
    elif not partial and not cfg.get('secret'):
        raise ValidationError('Webhook signing secret is required for new webhook rules.')
    elif existing.get('secret'):
        cfg['secret'] = existing['secret']

    if authorization_header is not None:
        auth_s = (authorization_header or '').strip()
        if auth_s:
            cfg['authorization_header'] = auth_s
        else:
            cfg.pop('authorization_header', None)
    elif existing.get('authorization_header'):
        cfg['authorization_header'] = existing['authorization_header']

    if is_superuser:
        if allow_private_urls is True:
            cfg['allow_private_urls'] = True
        elif allow_private_urls is False:
            cfg.pop('allow_private_urls', None)
    elif not partial:
        if existing.get('allow_private_urls'):
            cfg['allow_private_urls'] = True
    return cfg


def mask_config_for_response(config: dict, action_kind: str) -> dict:
    cfg = dict(config or {})
    if action_kind == ActionRule.ACTION_WEBHOOK:
        cfg.pop('secret', None)
        cfg.pop('authorization_header', None)
        cfg['secret_set'] = bool((config or {}).get('secret'))
        cfg['authorization_header_set'] = bool((config or {}).get('authorization_header'))
    return cfg
