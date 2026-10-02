"""HTTP client for Shellui email-service.

The API key and message variables (including magic-link URLs) are never written to logs.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlparse

import requests
from django.conf import settings

from apps.actions.webhook_retry import parse_retry_after_header

logger = logging.getLogger(__name__)

SERVICE_NAME = 'identity'
TEMPLATE_MAGIC_LINK = 'identity.auth.magic_link.requested'
TEMPLATE_INVITED = 'identity.user.invited'
DIRECT_SEND_EVENT_TYPES = frozenset({TEMPLATE_MAGIC_LINK, TEMPLATE_INVITED})
MAGIC_LINK_TTL_SECONDS = 120
INVITATION_TTL_SECONDS = 300

# email-service caller policy: these responses are not retried unchanged.
_PERMANENT_STATUSES = frozenset({400, 401, 403, 404, 422})
_RETRYABLE_STATUSES = frozenset({409, 429})


class EmailServiceUnreachable(Exception):
    """Network failure, timeout, or 5xx after the caller retry policy."""


class EmailServiceRejected(Exception):
    """email-service answered. Do not fall back to SMTP.

    ``retryable`` is set for ``429`` and ``409 lane_paused`` after the caller retry
    budget. Event delivery may try again later. Direct send returns an error.
    """

    def __init__(self, *, status: int, error_code: str, retryable: bool = False) -> None:
        super().__init__(error_code or str(status))
        self.status = status
        self.error_code = error_code or 'request_failed'
        self.retryable = retryable


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


def _retryable(status: int, error_code: str) -> bool:
    if status in _PERMANENT_STATUSES:
        return False
    if status == 409:
        return error_code == 'lane_paused'
    if status in _RETRYABLE_STATUSES:
        return True
    if 500 <= status < 600:
        return True
    return False


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


def post_json(path: str, body: dict) -> dict:
    """
    POST ``path`` (for example ``/api/v1/send``) with the service key.

    Retries ``409 lane_paused``, ``429``, and transport or 5xx failures with the same body.
    ``400``, ``401``, ``403``, ``404``, and ``422`` are not retried.
    Exhausted ``429`` and ``lane_paused`` raise ``EmailServiceRejected`` (retryable) so callers
    do not fall back to SMTP. Transport failures and 5xx raise ``EmailServiceUnreachable``.
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
    attempts = _max_attempts()
    last_status = None
    for attempt in range(1, attempts + 1):
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
            if attempt >= attempts:
                raise EmailServiceUnreachable from None
            continue
        last_status = response.status_code
        if 300 <= response.status_code < 400:
            logger.warning('email_service_redirect_rejected path=%s status=%s', path, response.status_code)
            raise EmailServiceUnreachable from None
        if response.status_code == 202:
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            return payload
        code = _error_code(response)
        logger.warning(
            'email_service_rejected path=%s status=%s error_code=%s attempt=%s',
            path,
            response.status_code,
            code or 'request_failed',
            attempt,
        )
        if _retryable(response.status_code, code) and attempt < attempts:
            _pause(attempt, response)
            continue
        if response.status_code >= 500:
            raise EmailServiceUnreachable from None
        raise EmailServiceRejected(
            status=response.status_code,
            error_code=code or 'request_failed',
            retryable=_retryable(response.status_code, code),
        ) from None
    logger.warning('email_service_unreachable path=%s status=%s', path, last_status)
    raise EmailServiceUnreachable from None
