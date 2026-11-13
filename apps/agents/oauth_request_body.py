"""Parse MCP OAuth POST bodies (RFC 6749 form-urlencoded, JSON for compatibility)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl

from django.http import HttpRequest, JsonResponse, QueryDict


def oauth_error(error: str, *, status: int = 400, description: str | None = None) -> JsonResponse:
    payload: dict[str, str] = {'error': error}
    if description:
        payload['error_description'] = description
    return JsonResponse(payload, status=status)


def _flat_querydict(qd: QueryDict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in qd:
        values = qd.getlist(key)
        if len(values) == 1:
            out[key] = values[0]
        else:
            out[key] = values
    return out


def parse_oauth_post_body(request: HttpRequest) -> tuple[dict[str, Any] | None, JsonResponse | None]:
    """Token and dynamic registration requests: ``application/x-www-form-urlencoded`` or JSON."""
    content_type = (request.content_type or '').split(';', 1)[0].strip().lower()
    raw = request.body or b''

    if content_type == 'application/json' or (not content_type and raw[:1] in (b'{', b'[')):
        try:
            decoded = json.loads(raw.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return None, oauth_error('invalid_request')
        if not isinstance(decoded, dict):
            return None, oauth_error('invalid_request')
        return decoded, None

    if content_type in ('application/x-www-form-urlencoded', 'multipart/form-data', ''):
        if request.POST:
            return _flat_querydict(request.POST), None
        if raw:
            try:
                text = raw.decode('utf-8')
            except UnicodeDecodeError:
                return None, oauth_error('invalid_request')
            pairs = parse_qsl(text, keep_blank_values=True)
            if pairs:
                qd = QueryDict('', mutable=True)
                for key, value in pairs:
                    qd.appendlist(key, value)
                return _flat_querydict(qd), None
        return {}, None

    return None, oauth_error('invalid_request')


def redirect_uris_from_body(body: dict[str, Any]) -> list[str]:
    raw = body.get('redirect_uris')
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        if text.startswith('['):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return [text]
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        return [text]
    return []
