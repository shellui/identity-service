"""Validated audit outcomes for MCP call logs (internal ingest and human-readable APIs)."""

from __future__ import annotations

# Five canonical strings stored on ingest; rate and timeout map to ``failed`` with error_code.
OUTCOME_ALLOWED = 'allowed'
OUTCOME_FAILED = 'failed'
OUTCOME_DENIED = 'denied'
OUTCOME_PENDING_APPROVAL = 'pending_approval'
OUTCOME_SESSION_USED = 'session_used'

CANONICAL_OUTCOMES = frozenset(
    {
        OUTCOME_ALLOWED,
        OUTCOME_FAILED,
        OUTCOME_DENIED,
        OUTCOME_PENDING_APPROVAL,
        OUTCOME_SESSION_USED,
    }
)

# Legacy DB or gateway strings mapped on read paths only (never trusted on ingest).
LEGACY_OUTCOME_ALIASES: dict[str, str] = {
    'success': OUTCOME_ALLOWED,
    'error': OUTCOME_FAILED,
    'rate_limited': OUTCOME_FAILED,
    'timeout': OUTCOME_FAILED,
}


def canonical_outcome_ingest(raw: str | None) -> str | None:
    """Normalize an explicit outcome string for internal ingest. No HTTP status fallback."""
    s = (raw or '').strip().lower()
    if not s:
        return None
    if s in LEGACY_OUTCOME_ALIASES:
        return LEGACY_OUTCOME_ALIASES[s]
    if s in CANONICAL_OUTCOMES:
        return s
    return None


def display_outcome_for_read(stored: str | None, *, result: str, status_code: int, error_code: str) -> str:
    """Map stored rows and legacy strings to the five canonical labels for UIs."""
    s = (stored or '').strip().lower()
    if s in CANONICAL_OUTCOMES:
        return s
    if s in LEGACY_OUTCOME_ALIASES:
        return LEGACY_OUTCOME_ALIASES[s]
    r = (result or '').strip().lower()
    if r in LEGACY_OUTCOME_ALIASES:
        return LEGACY_OUTCOME_ALIASES[r]
    if r in CANONICAL_OUTCOMES:
        return r
    ec = (error_code or '').strip().lower()
    if ec in ('timeout', 'rate_limited'):
        return OUTCOME_FAILED
    return OUTCOME_FAILED


def normalized_resource_label(tool: str, method: str, path: str) -> str:
    """Short safe label for audit UIs: prefer tool name, else METHOD path (truncated)."""
    tool_s = (tool or '').strip()
    if tool_s:
        return tool_s[:255]
    method_s = (method or '').strip().upper()[:10]
    path_s = (path or '').strip()[:400]
    if method_s and path_s:
        return f'{method_s} {path_s}'.strip()[:500]
    if path_s:
        return path_s[:500]
    return method_s or 'mcp_call'
