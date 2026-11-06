"""Validated audit outcomes for MCP call logs (internal ingest and human-readable APIs)."""

from __future__ import annotations

# Exact string stored and returned; callers must not invent values from raw tool output.
OUTCOME_SUCCESS = 'success'
OUTCOME_ERROR = 'error'
OUTCOME_DENIED = 'denied'
OUTCOME_RATE_LIMITED = 'rate_limited'
OUTCOME_TIMEOUT = 'timeout'

CANONICAL_OUTCOMES = frozenset(
    {
        OUTCOME_SUCCESS,
        OUTCOME_ERROR,
        OUTCOME_DENIED,
        OUTCOME_RATE_LIMITED,
        OUTCOME_TIMEOUT,
    }
)


def canonical_outcome(raw: str | None, *, status_code: int) -> str:
    """Map an optional outcome string plus HTTP status to a canonical outcome enum."""
    s = (raw or '').strip().lower()
    if s in CANONICAL_OUTCOMES:
        return s
    if 200 <= status_code < 400:
        return OUTCOME_SUCCESS
    return OUTCOME_ERROR


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
