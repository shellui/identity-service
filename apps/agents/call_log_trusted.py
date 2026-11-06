"""Strict validation for gateway-forwarded MCP call log metadata (ai-service #24)."""

from __future__ import annotations

import re
import uuid
from typing import Any

from django.core.exceptions import ValidationError

# Access kind from gateway (must match OpenAPI / gateway enum).
ACCESS_KIND_READ = 'read'
ACCESS_KIND_WRITE = 'write'
ACCESS_KIND_DESTRUCTIVE = 'destructive'
ALLOWED_ACCESS_KINDS = frozenset({ACCESS_KIND_READ, ACCESS_KIND_WRITE, ACCESS_KIND_DESTRUCTIVE})

# Known terminal outcomes (no raw provider errors or stack traces).
CALL_RESULT_SUCCESS = 'success'
CALL_RESULT_ERROR = 'error'
CALL_RESULT_DENIED = 'denied'
CALL_RESULT_TIMEOUT = 'timeout'
CALL_RESULT_CANCELLED = 'cancelled'
CALL_RESULT_UNAVAILABLE = 'unavailable'
ALLOWED_CALL_RESULTS = frozenset(
    {
        CALL_RESULT_SUCCESS,
        CALL_RESULT_ERROR,
        CALL_RESULT_DENIED,
        CALL_RESULT_TIMEOUT,
        CALL_RESULT_CANCELLED,
        CALL_RESULT_UNAVAILABLE,
    }
)

ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {
        'agent_id',
        'company_id',
        'service',
        'tool',
        'method',
        'path',
        'status',
        'duration_ms',
        'result',
        'client_ip',
        'arguments',
        'operation_title',
        'access_kind',
        'operation_result',
        'resource_label',
        'approval_request_id',
    }
)

_TITLE_MAX = 200
_RESOURCE_LABEL_MAX = 120

# Titles: no control characters; printable unicode ok; length bounded.
_TITLE_PATTERN = re.compile(r'^[\S ]+$', re.UNICODE)
_RESOURCE_PATTERN = re.compile(r'^[\w\- ./:~+@%]{1,120}$', re.UNICODE)


def assert_allowlisted_keys(body: dict[str, Any]) -> None:
    extra = set(body.keys()) - ALLOWED_TOP_LEVEL_KEYS
    if extra:
        raise ValidationError(f'Unknown fields: {sorted(extra)}')


def _clean_short_text(raw: str, *, max_len: int, pattern: re.Pattern[str], label: str) -> str:
    s = (raw or '').strip()
    if len(s) > max_len:
        raise ValidationError(f'{label} too long.')
    if not s:
        raise ValidationError(f'{label} required.')
    if not pattern.match(s):
        raise ValidationError(f'{label} has invalid characters.')
    return s


def parse_operation_title(raw: Any) -> str:
    if raw is None:
        raise ValidationError('operation_title required.')
    return _clean_short_text(str(raw), max_len=_TITLE_MAX, pattern=_TITLE_PATTERN, label='operation_title')


def parse_resource_label(raw: Any) -> str:
    if raw is None:
        raise ValidationError('resource_label required.')
    return _clean_short_text(
        str(raw), max_len=_RESOURCE_LABEL_MAX, pattern=_RESOURCE_PATTERN, label='resource_label'
    )


def parse_access_kind(raw: Any) -> str:
    if raw is None:
        raise ValidationError('access_kind required.')
    s = str(raw).strip().lower()
    if s not in ALLOWED_ACCESS_KINDS:
        raise ValidationError('access_kind must be read, write, or destructive.')
    return s


def parse_operation_result(raw: Any) -> str:
    if raw is None:
        raise ValidationError('operation_result required.')
    s = str(raw).strip().lower()
    if s not in ALLOWED_CALL_RESULTS:
        raise ValidationError('operation_result is not allowed.')
    return s


def parse_approval_request_id(raw: Any) -> uuid.UUID | None:
    if raw is None or raw == '':
        return None
    try:
        return uuid.UUID(str(raw).strip())
    except (ValueError, TypeError) as exc:
        raise ValidationError('approval_request_id must be a uuid.') from exc
