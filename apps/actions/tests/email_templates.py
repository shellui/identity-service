"""Test stand-in for admin-compiled rule templates (the browser renders real HTML)."""

from __future__ import annotations

import html as html_lib

from apps.actions.email_template_defaults import (
    read_default_subject_source,
    resolve_default_document,
)


def _render_inline(node: dict) -> str:
    text = html_lib.escape(node.get('text') or '')
    for mark in node.get('marks') or []:
        if mark.get('type') == 'bold':
            text = f'<strong>{text}</strong>'
        elif mark.get('type') == 'link':
            href = html_lib.escape((mark.get('attrs') or {}).get('href') or '', quote=True)
            text = f'<a href="{href}">{text}</a>'
    return text


def _render_node(node: dict) -> str:
    kind = node.get('type')
    children = node.get('content') or []
    if kind == 'text':
        return _render_inline(node)
    inner = ''.join(_render_node(child) for child in children)
    if kind == 'paragraph':
        return f'<p>{inner}</p>'
    if kind == 'heading':
        level = int((node.get('attrs') or {}).get('level') or 1)
        return f'<h{level}>{inner}</h{level}>'
    if kind == 'button':
        href = html_lib.escape((node.get('attrs') or {}).get('href') or '', quote=True)
        return f'<a class="button" href="{href}">{inner}</a>'
    return inner


def compiled_email_template(event_type: str, language: str) -> dict:
    document, _lang = resolve_default_document(
        event_type, preferred=language, use_user_preference=True
    )
    subject, _sub_lang = read_default_subject_source(
        event_type, preferred=language, use_user_preference=True
    )
    body = _render_node(document)
    return {
        'subject': (subject or '').strip(),
        'html': f'<!DOCTYPE html><html lang="{language}"><body>{body}</body></html>',
        'document': document,
    }


def compiled_email_templates(event_type: str, languages: tuple[str, ...] = ('en', 'fr')) -> dict:
    return {lang: compiled_email_template(event_type, lang) for lang in languages}


def email_rule_config(event_type: str, **config) -> dict:
    """Email ``ActionRule.config`` with compiled en/fr templates from filesystem defaults."""
    return {'email_templates': compiled_email_templates(event_type), **config}
