"""Per-request id for log correlation, plus a warning log for slow requests.

The id comes from the inbound ``X-Request-ID`` header when it looks safe, otherwise a new
one is generated. It is added to every log line (see ``LOGGING`` in settings) and returned
in the ``X-Request-ID`` response header, so the gunicorn access log can print it too.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from contextvars import ContextVar

from django.conf import settings

request_id_var: ContextVar[str] = ContextVar('request_id', default='-')

logger = logging.getLogger('config.request')

REQUEST_ID_HEADER = 'X-Request-ID'
# Letters, digits and a few separators only, so a client cannot inject spaces or
# control characters into log lines.
_SAFE_REQUEST_ID_RE = re.compile(r'^[A-Za-z0-9._:-]{1,64}$')


def _new_request_id() -> str:
    return uuid.uuid4().hex


def resolve_request_id(incoming: str | None) -> str:
    """Return the inbound id when it is safe to log, otherwise a new random id."""
    value = (incoming or '').strip()
    if value and _SAFE_REQUEST_ID_RE.fullmatch(value):
        return value
    return _new_request_id()


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, 'request_id'):
            # django.request logs 4xx responses after the middleware chain has returned,
            # but passes the request in the record, so read the id from there first.
            request = getattr(record, 'request', None)
            record.request_id = getattr(request, 'request_id', None) or request_id_var.get()
        return True


class RequestIdMiddleware:
    """Assign a request id, echo it as ``X-Request-ID`` and warn about slow requests.

    Requests slower than ``SLOW_REQUEST_THRESHOLD_SECONDS`` are logged as a warning with
    the method, path, status and duration. Set the threshold to 0 to turn this off.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = resolve_request_id(request.headers.get(REQUEST_ID_HEADER))
        request.request_id = request_id
        token = request_id_var.set(request_id)
        started = time.monotonic()
        try:
            response = self.get_response(request)
            response[REQUEST_ID_HEADER] = request_id
            self._log_if_slow(request, response.status_code, time.monotonic() - started)
            return response
        finally:
            request_id_var.reset(token)

    @staticmethod
    def _log_if_slow(request, status_code: int, elapsed: float) -> None:
        threshold = float(getattr(settings, 'SLOW_REQUEST_THRESHOLD_SECONDS', 0) or 0)
        if threshold <= 0 or elapsed < threshold:
            return
        logger.warning(
            'Slow request: %s %s status=%s duration_ms=%d threshold_ms=%d',
            request.method,
            request.path,
            status_code,
            int(elapsed * 1000),
            int(threshold * 1000),
        )
