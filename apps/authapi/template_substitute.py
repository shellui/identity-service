"""Variable-only substitution for action email HTML and subjects.

Stored overrides and filesystem defaults are raw HTML (or plain subject strings)
with ``{{ dotted.path }}`` placeholders. Django ``{% %}`` tags are not allowed
on the send path; use this module instead of ``Template.render``.

Security:
- HTML mode HTML-escapes every interpolated value (defeats markup injection).
- Placeholders inside URL attributes (``href``, ``src``, …) are scheme-checked
  after resolution (``http`` / ``https`` / ``mailto`` / ``tel`` / ``#`` only).
- Plain mode (subjects) does not HTML-escape, but strips CR/LF to avoid header
  injection.
"""

from __future__ import annotations

import html
import re
from typing import Any, Literal
from urllib.parse import urlparse

from django.core.exceptions import ValidationError

SubstituteMode = Literal['html', 'plain']

_DJANGO_TAG_RE = re.compile(r'\{%|\%\}')
_PLACEHOLDER_RE = re.compile(
    r'\{\{\s*(?P<expr>[^{}]+?)\s*\}\}',
    re.DOTALL,
)

# True when the placeholder sits inside an unclosed quoted URL attribute value.
_URL_ATTR_BEFORE_RE = re.compile(
    r'(?is)'
    r'\b(?:href|src|xlink:href|poster|action|formaction|cite)'
    r'\s*=\s*'
    r'(?P<q>["\'])'
    r'(?:(?!(?P=q)).)*$',
)

_SAFE_URL_SCHEMES = frozenset({'http', 'https', 'mailto', 'tel'})


def assert_no_django_template_tags(text: str, *, field_label: str = 'template') -> None:
    if _DJANGO_TAG_RE.search(text):
        raise ValidationError(
            f'{field_label} must not contain Django template tags (`{{%` / `%}}`); '
            'use literal `{{ variable }}` placeholders only.'
        )


def _lookup_path(context: dict[str, Any], path: str) -> Any:
    current: Any = context
    for part in path.split('.'):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _apply_filter(value: Any, filter_part: str) -> str:
    filter_part = filter_part.strip()
    if not filter_part:
        return '' if value is None else str(value)

    if filter_part.startswith('default:'):
        default_raw = filter_part[len('default:') :].strip()
        if default_raw.startswith('"') and default_raw.endswith('"'):
            default_val = default_raw[1:-1]
        elif default_raw.startswith("'") and default_raw.endswith("'"):
            default_val = default_raw[1:-1]
        else:
            default_val = default_raw
        if value is None or value == '':
            return str(default_val)
        return str(value)

    if filter_part == 'title':
        if value is None:
            return ''
        return str(value).title()

    if value is None:
        return ''
    return str(value)


def _resolve_expr(expr: str, context: dict[str, Any]) -> str:
    expr = expr.strip()
    path_part, _, filter_chain = expr.partition('|')
    path_part = path_part.strip()
    value = _lookup_path(context, path_part)

    if filter_chain:
        for segment in filter_chain.split('|'):
            segment = segment.strip()
            if not segment:
                continue
            if segment.startswith('default:'):
                default_raw = segment[len('default:') :].strip()
                if (default_raw.startswith('"') and default_raw.endswith('"')) or (
                    default_raw.startswith("'") and default_raw.endswith("'")
                ):
                    default_val = default_raw[1:-1]
                else:
                    looked = _lookup_path(context, default_raw)
                    default_val = looked if looked is not None else default_raw
                if value is None or value == '':
                    value = default_val
            elif segment == 'title':
                value = '' if value is None else str(value).title()
            else:
                value = _apply_filter(value, segment)
    if value is None:
        return ''
    return str(value)


def _in_url_attribute(text: str, pos: int) -> bool:
    window = text[max(0, pos - 512) : pos]
    return _URL_ATTR_BEFORE_RE.search(window) is not None


def sanitize_action_email_url(value: str) -> str:
    """Allow only safe absolute URL schemes (or ``#``). Invalid → empty string."""
    trimmed = value.strip()
    if not trimmed:
        return ''
    if trimmed == '#':
        return '#'
    try:
        parsed = urlparse(trimmed)
    except Exception:
        return ''
    scheme = (parsed.scheme or '').lower()
    if scheme not in _SAFE_URL_SCHEMES:
        return ''
    # Require a hierarchical part for http(s); mailto/tel need a path/opaque part.
    if scheme in {'http', 'https'} and not parsed.netloc:
        return ''
    if scheme in {'mailto', 'tel'} and not (parsed.path or parsed.netloc):
        return ''
    return trimmed


def _encode_html_value(raw: str, *, in_url_attr: bool) -> str:
    if in_url_attr:
        safe = sanitize_action_email_url(raw)
        return html.escape(safe, quote=True)
    return html.escape(raw, quote=True)


def _encode_plain_value(raw: str) -> str:
    # Subjects are not HTML; still neutralize newlines for header safety.
    return raw.replace('\r', ' ').replace('\n', ' ')


def substitute_action_email_template(
    text: str,
    context: dict[str, Any],
    *,
    mode: SubstituteMode = 'html',
) -> str:
    """Replace ``{{ envelope.company.name }}``-style placeholders from *context*.

    ``mode='html'`` (default): escape values; scheme-check URL attributes.
    ``mode='plain'``: for email subjects — no HTML escaping, strip CR/LF.
    """

    def repl(match: re.Match[str]) -> str:
        raw = _resolve_expr(match.group('expr'), context)
        if mode == 'plain':
            return _encode_plain_value(raw)
        return _encode_html_value(raw, in_url_attr=_in_url_attribute(text, match.start()))

    return _PLACEHOLDER_RE.sub(repl, text)
