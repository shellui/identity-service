"""Variable-only substitution for action email HTML and subjects.

Stored overrides and filesystem defaults are raw HTML (or plain subject strings)
with ``{{ dotted.path }}`` placeholders. Django ``{% %}`` tags are not allowed
on the send path; use this module instead of ``Template.render``.
"""

from __future__ import annotations

import re
from typing import Any

from django.core.exceptions import ValidationError

_DJANGO_TAG_RE = re.compile(r'\{%|\%\}')
_PLACEHOLDER_RE = re.compile(
    r'\{\{\s*(?P<expr>[^{}]+?)\s*\}\}',
    re.DOTALL,
)


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
            default_val = _lookup_path({'data': value if False else {}, **{}}, default_raw)
            # default may reference another path in full context; handled in _resolve_expr
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


def substitute_action_email_template(text: str, context: dict[str, Any]) -> str:
    """Replace ``{{ envelope.company.name }}``-style placeholders from *context*."""

    def repl(match: re.Match[str]) -> str:
        return _resolve_expr(match.group('expr'), context)

    return _PLACEHOLDER_RE.sub(repl, text)
