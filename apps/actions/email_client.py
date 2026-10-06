"""HTTP client for Shellui email-service.

The API key and message variables (including magic-link URLs) are never written to logs.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlparse

import requests
from django.conf import settings

from apps.actions.webhook_retry import is_permanent_http_status, parse_retry_after_header
from config.request_context import request_id_var

logger = logging.getLogger(__name__)

SERVICE_NAME = 'identity'
TEMPLATE_MAGIC_LINK = 'identity.auth.magic_link.requested'
TEMPLATE_INVITED = 'identity.user.invited'
DIRECT_SEND_EVENT_TYPES = frozenset({TEMPLATE_MAGIC_LINK, TEMPLATE_INVITED})
MAGIC_LINK_TTL_SECONDS = 120
INVITATION_TTL_SECONDS = 300

# Auth-lane refusals returned to the client. None of these are sent again over SMTP.
PASSTHROUGH_SEND_CODES = {
    'recipient_suppressed': 422,
    'company_rate_limited': 429,
    'recipient_rate_limited': 429,
    'provider_not_configured': 409,
    'auth_link_missing': 400,
    'auth_link_host_not_allowed': 400,
}


class EmailServiceUnreachable(Exception):
    """Network failure, timeout, redirect, or 5xx."""

    def __init__(self, *, status: int | None = None, error_code: str = '', retry_after: int | None = None) -> None:
        super().__init__(error_code or 'unreachable')
        self.status = status
        self.error_code = error_code
        self.retry_after = retry_after


class EmailServiceRejected(Exception):
    """email-service answered with a non-2xx that is not treated as unreachable.

    ``retryable`` follows the caller retry table (not the permanent 4xx set).
    Direct send does not fall back to SMTP for this exception.
    """

    def __init__(
        self,
        *,
        status: int,
        error_code: str,
        retryable: bool = False,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(error_code or str(status))
        self.status = status
        self.error_code = error_code or 'request_failed'
        self.retryable = retryable
        self.retry_after = retry_after


class EmailUnavailable(Exception):
    """Neither email-service nor SMTP accepted the message."""


class RecipientSuppressed(Exception):
    """Auth lane refused the address. Do not retry and do not fall back to SMTP."""


def email_service_configured() -> bool:
    return bool(_api_key())


def magic_link_idempotency_key(*, company_id: int, user_id: int | None, request_id) -> str:
    """Stable for one magic-link row. Does not include the raw token."""
    user_part = str(user_id) if user_id else '0'
    return f'magic-link-{company_id}-user-{user_part}-{request_id}'


def invitation_idempotency_key(*, company_id: int, invitation_id: int) -> str:
    return f'invitation-{company_id}-{invitation_id}'


def _api_key() -> str:
    return str(getattr(settings, 'EMAIL_SERVICE_API_KEY', '') or '').strip()


def _base_url() -> str:
    raw = str(getattr(settings, 'EMAIL_SERVICE_URL', '') or '').strip() or 'https://email.shellui.com'
    return raw.rstrip('/')


def _timeout() -> float:
    return float(getattr(settings, 'EMAIL_SERVICE_TIMEOUT_SECONDS', 5.0) or 5.0)


def _max_attempts() -> int:
    return max(1, int(getattr(settings, 'EMAIL_SERVICE_SEND_ATTEMPTS', 3) or 3))


def _sleep_cap() -> float:
    return max(0.0, float(getattr(settings, 'EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS', 1.0) or 0.0))


def _origin_ok(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {'https', 'http'} or not parsed.netloc:
        return False
    if parsed.username or parsed.password:
        return False
    return True


def _error_code(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return ''
    if not isinstance(payload, dict):
        return ''
    code = payload.get('error_code')
    return code.strip() if isinstance(code, str) else ''


def _outcome(status: int) -> str:
    """``ok``, ``permanent``, ``retry``, or ``unreachable`` per the email-service caller table."""
    if 200 <= status < 300:
        return 'ok'
    if 300 <= status < 400 or status >= 500:
        return 'unreachable'
    if is_permanent_http_status(status):
        return 'permanent'
    return 'retry'


def _pause(attempt: int, response: requests.Response | None) -> None:
    """Delay before a retry. Connection failures retry immediately. 429 and lane_paused wait."""
    if response is None:
        return
    cap = _sleep_cap()
    if cap <= 0:
        return
    retry_after = parse_retry_after_header(response.headers.get('Retry-After'))
    if retry_after is None:
        retry_after = min(30, 2 ** max(0, attempt - 1))
    delay = min(cap, float(retry_after))
    if delay > 0:
        time.sleep(delay)


def _retry_after(response: requests.Response) -> int | None:
    if response.status_code not in (429, 503):
        return None
    return parse_retry_after_header(response.headers.get('Retry-After'))


def _read_json(response: requests.Response) -> dict:
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def post_json(path: str, body: dict, *, attempts: int | None = None) -> dict:
    """
    POST ``path`` with the service key.

    Direct send (``/api/v1/send``) retries transport failures, 5xx, and retryable 4xx
    up to ``EMAIL_SERVICE_SEND_ATTEMPTS``. Exhausted retryable 4xx raise
    ``EmailServiceRejected``. Transport failures and 5xx raise ``EmailServiceUnreachable``.

    Event ingest passes ``attempts=1``. The outbox applies the caller retry table:
    2xx is done (including ``skipped_reason``), permanent 4xx are not retried, and every
    other failure is retried with the webhook backoff.
    """
    key = _api_key()
    if not key:
        raise EmailServiceUnreachable
    origin = _base_url()
    if not _origin_ok(origin):
        logger.warning('email_service_origin_rejected')
        raise EmailServiceUnreachable
    url = f'{origin}{path}'
    headers = {
        'Authorization': f'Bearer {key}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'shellui-identity-email/1.0',
    }
    # Same id as identity log lines (request id, or ``sjr-<run id>`` inside a scheduled job).
    request_id = request_id_var.get()
    if request_id and request_id != '-':
        headers['X-Request-ID'] = request_id
    total = _max_attempts() if attempts is None else max(1, int(attempts))
    last_status = None
    for attempt in range(1, total + 1):
        response = None
        try:
            response = requests.post(
                url,
                json=body,
                headers=headers,
                timeout=_timeout(),
                allow_redirects=False,
            )
        except requests.RequestException:
            logger.warning(
                'email_service_unreachable path=%s attempt=%s',
                path,
                attempt,
            )
            if attempt >= total:
                raise EmailServiceUnreachable from None
            continue
        last_status = response.status_code
        outcome = _outcome(response.status_code)
        if outcome == 'ok':
            return _read_json(response)
        code = _error_code(response) or 'request_failed'
        retry_after = _retry_after(response)
        logger.warning(
            'email_service_rejected path=%s status=%s error_code=%s attempt=%s',
            path,
            response.status_code,
            code,
            attempt,
        )
        if outcome == 'unreachable':
            if attempt >= total:
                raise EmailServiceUnreachable(
                    status=response.status_code,
                    error_code=code,
                    retry_after=retry_after,
                ) from None
            _pause(attempt, response)
            continue
        if outcome == 'retry' and attempt < total:
            _pause(attempt, response)
            continue
        raise EmailServiceRejected(
            status=response.status_code,
            error_code=code,
            retryable=outcome == 'retry',
            retry_after=retry_after,
        ) from None
    logger.warning('email_service_unreachable path=%s status=%s', path, last_status)
    raise EmailServiceUnreachable from None


def post_event(body: dict) -> dict:
    """One ``POST /api/v1/events``. The outbox owns retries."""
    return post_json('/api/v1/events', body, attempts=1)
