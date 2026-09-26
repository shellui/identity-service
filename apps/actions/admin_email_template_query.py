"""Query parsing for admin email template preview endpoints."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response

from apps.actions.email_i18n import normalize_language_code


def parse_email_template_language_codes(raw: str | None) -> tuple[list[str], list[str]]:
    """
    Split a comma-separated language list, normalize codes, and dedupe (order preserved).

    Returns ``(normalized_codes, invalid_raw_tokens)``.
    """
    if not raw or not str(raw).strip():
        return [], []
    invalid: list[str] = []
    seen: set[str] = set()
    normalized: list[str] = []
    for part in str(raw).split(','):
        token = part.strip()
        if not token:
            continue
        code = normalize_language_code(token)
        if not code:
            invalid.append(token)
            continue
        if code in seen:
            continue
        seen.add(code)
        normalized.append(code)
    return normalized, invalid


def requested_email_template_languages(request) -> tuple[None | str | list[str], Response | None]:
    """
    Resolve ``language`` / ``languages`` query params for template preview APIs.

    - No param: ``(None, None)`` (single response using deployment default).
    - One locale: ``(code, None)`` (legacy single-object body).
    - Two or more: ``(list[str], None)`` (batch body with ``templates`` map).
    """
    languages_raw = request.GET.get('languages')
    language_raw = request.GET.get('language')

    if languages_raw is not None and str(languages_raw).strip():
        source = languages_raw
    elif language_raw is not None and str(language_raw).strip():
        source = language_raw
    else:
        return None, None

    codes, invalid = parse_email_template_language_codes(source)
    if invalid:
        joined = ', '.join(invalid)
        return None, Response(
            {'error': f'Invalid language code(s): {joined}.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if not codes:
        return None, Response(
            {'error': 'At least one language code is required.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if len(codes) == 1:
        return codes[0], None
    return codes, None
