"""Allowlisted error_code values for MCP call log ingest (personal activity)."""

from __future__ import annotations

# Union of ai-service gateway codes and identity-specific codes (strict allowlist).
ALLOWED_ERROR_CODES = frozenset(
    {
        'bad_request',
        'unauthorized',
        'forbidden',
        'not_found',
        'conflict',
        'rate_limited',
        'timeout',
        'upstream_error',
        'internal_error',
        'unknown',
        'denied',
        'pending_approval',
        'waiting_approval',
        'expired',
        'out_of_sync',
        'identity_unreachable',
        'invalid_grant',
        'permission_changed',
        'request_expired',
        'downstream_error',
        'server_error',
    },
)


def sanitize_error_code(raw: object) -> str | None:
    code = str(raw or '').strip().lower()[:64]
    return code if code in ALLOWED_ERROR_CODES else None
