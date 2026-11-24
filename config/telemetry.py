"""Process-wide OpenTelemetry setup for identity-service.

Traces and metrics stay off until an OTLP endpoint is configured. Importing this
module does not import the OpenTelemetry SDK.
"""

from __future__ import annotations

import logging
import os
import sys
import tomllib
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SERVICE_NAME = 'identity-service'
_ROLE_ATTRIBUTE = 'shellui.instance_role'
_PYPROJECT = Path(__file__).resolve().parent.parent / 'pyproject.toml'


def instance_role() -> str:
    """``global`` (identity-global), ``region``, or ``standalone``."""
    raw = os.getenv('SHELLUI_INSTANCE_ROLE', '').strip().lower()
    if raw in {'global', 'region'}:
        return raw
    return 'standalone'


def package_version() -> str:
    with _PYPROJECT.open('rb') as fh:
        data = tomllib.load(fh)
    return str(data.get('project', {}).get('version', '')).strip()


def _resource_keys(raw: str) -> set[str]:
    keys: set[str] = set()
    for part in raw.split(','):
        if '=' in part:
            keys.add(part.split('=', 1)[0].strip())
    return keys


def _ensure_instance_role(role: str) -> None:
    """Add ``shellui.instance_role`` unless the operator already set it."""
    raw = os.getenv('OTEL_RESOURCE_ATTRIBUTES', '')
    if _ROLE_ATTRIBUTE in _resource_keys(raw):
        return
    extra = f'{_ROLE_ATTRIBUTE}={role}'
    merged = f'{raw},{extra}' if raw.strip() else extra
    os.environ['OTEL_RESOURCE_ATTRIBUTES'] = merged


def _region() -> str:
    return os.getenv('SHELLUI_REGION', '').strip()


def _environment() -> str:
    return os.getenv('SENTRY_ENVIRONMENT', '').strip()


def setup_process_telemetry() -> bool:
    """Enable telemetry for this process. Safe to call again after a fork."""
    endpoint = os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', '').strip()
    headers = os.getenv('OTEL_EXPORTER_OTLP_HEADERS', '')
    if headers.strip() and not endpoint:
        logger.warning(
            'OTEL_EXPORTER_OTLP_HEADERS is set without OTEL_EXPORTER_OTLP_ENDPOINT. Telemetry stays off.',
        )
    role = instance_role()
    _ensure_instance_role(role)
    service_name = os.getenv('OTEL_SERVICE_NAME', '').strip() or SERVICE_NAME
    from shellui_django.telemetry import setup_telemetry

    enabled = setup_telemetry(
        service_name,
        service_version=package_version(),
        environment=_environment() or None,
        region=_region() or None,
    )
    if enabled:
        register_metrics()
        logger.info(
            'OpenTelemetry enabled service=%s role=%s region=%s',
            service_name,
            role,
            _region(),
        )
    return enabled


def register_metrics() -> None:
    """Bind observable gauges once Django models are loaded and telemetry is on.

    ``AppConfig.ready()`` runs before ``apps.ready`` is set, so this checks
    ``models_ready``. The Celery worker skips the gauges: its thread pool shares
    one database connection, so the metric reader thread must not query there.
    Gunicorn publishes them, and starts its active request count at 0.
    """
    from django.apps import apps

    if not apps.models_ready or _in_celery_worker():
        return
    from apps.actions.scheduled_job_metrics import ensure_scheduled_job_metrics
    from apps.authapi.metrics import ensure_auth_metrics

    ensure_auth_metrics()
    ensure_scheduled_job_metrics()
    _publish_active_requests()


def _publish_active_requests() -> None:
    """Start ``http.server.active_requests`` at 0 in this web process.

    The Django instrumentation creates the series on the first traced request.
    Health checks are not traced, so a worker without real traffic exported no
    series at all and looked down to the "no telemetry" alert.
    """
    try:
        from opentelemetry.instrumentation.django.middleware.otel_middleware import _DjangoMiddleware
    except ImportError:
        return
    active_requests = getattr(_DjangoMiddleware, '_active_request_counter', None)
    if active_requests is not None:
        active_requests.add(0, {})


def tag_span(
    *,
    company_id: str | int | None = None,
    user_id: str | int | None = None,
    agent_id: str | int | None = None,
) -> None:
    """Attach opaque Shellui ids to the current span. No effect when telemetry is off."""
    from shellui_django.telemetry import set_shellui_attributes

    attributes: dict[str, str | int] = {}
    if agent_id is not None:
        attributes['agent_id'] = agent_id
    set_shellui_attributes(
        company_id=company_id,
        user_id=user_id,
        attributes=attributes or None,
    )


def inject_trace_context(headers: Mapping[str, str] | None = None) -> dict[str, str]:
    """Copy W3C trace context onto outbound headers. Unchanged when telemetry is off."""
    from shellui_django.telemetry._state import state

    merged = dict(headers or {})
    if not state.active:
        return merged
    from opentelemetry.propagate import inject

    inject(merged)
    return merged


def current_trace_context() -> Any:
    """Return the active context, or None when telemetry is off."""
    from shellui_django.telemetry._state import state

    if not state.active:
        return None
    from opentelemetry import context

    return context.get_current()


@contextmanager
def bind_trace_context(parent: Any) -> Iterator[None]:
    """Run a worker thread inside the request trace that queued it."""
    if parent is None:
        yield
        return
    from opentelemetry import context

    token = context.attach(parent)
    try:
        yield
    finally:
        context.detach(token)


class ShelluiSpanMiddleware:
    """Record the session user id on the request span when one is signed in."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        user = getattr(request, 'user', None)
        if user is not None and getattr(user, 'is_authenticated', False):
            tag_span(user_id=getattr(user, 'pk', None))
        return response


def _in_celery_worker() -> bool:
    return bool(sys.argv) and os.path.basename(sys.argv[0]) == 'celery'
