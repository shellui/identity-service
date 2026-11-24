"""OpenTelemetry metrics for scheduled jobs.

Runs happen in the Celery worker or a cron process, so values are read from
``ScheduledJobCounter`` and ``ScheduledJobState`` when the SDK collects them.
Attributes are ``job``, ``status``, and ``kind`` only.
"""

from __future__ import annotations

import logging
import time

from django.utils import timezone
from shellui_django.telemetry import canonical_metric_name, get_meter

from apps.actions.models import ScheduledJobCounter
from apps.actions.scheduled_jobs import (
    JOBS,
    RUN_STATUSES,
    beat_last_seen,
    ensure_states,
    is_overdue,
    redis_reachable,
    scheduler_enabled,
)

logger = logging.getLogger(__name__)

_METER = 'shellui.identity'
_bound_generation = -1
_CACHE_SECONDS = 1.0
_points_cache: dict = {'at': 0.0, 'points': None}

RUNS = 'shellui.auth.scheduled.job.runs'
ITEMS = 'shellui.auth.scheduled.job.items'
LAST_SUCCESS = 'shellui.auth.scheduled.job.last.success.timestamp.seconds'
LAST_RUN = 'shellui.auth.scheduled.job.last.run.timestamp.seconds'
DURATION = 'shellui.auth.scheduled.job.last.run.duration.seconds'
OVERDUE = 'shellui.auth.scheduled.job.overdue'
SCHEDULER_ENABLED = 'shellui.auth.scheduler.enabled'
REDIS_UP = 'shellui.auth.scheduler.redis.up'
BEAT_LAST_SEEN = 'shellui.auth.scheduler.beat.last.seen.timestamp.seconds'


def scheduled_job_points() -> list[tuple[str, dict[str, str], float]]:
    """Current observations as ``(instrument name, attributes, value)``."""
    now = timezone.now()
    states = ensure_states()
    counters = {(row.job, row.name): row.value for row in ScheduledJobCounter.objects.filter(job__in=list(JOBS))}
    points: list[tuple[str, dict[str, str], float]] = []
    for name, spec in JOBS.items():
        state = states[name]
        for status in RUN_STATUSES:
            points.append((RUNS, {'job': name, 'status': status}, float(counters.get((name, f'runs.{status}'), 0))))
        for kind in spec.item_kinds:
            points.append((ITEMS, {'job': name, 'kind': kind}, float(counters.get((name, f'items.{kind}'), 0))))
        points.append(
            (LAST_SUCCESS, {'job': name}, state.last_success_at.timestamp() if state.last_success_at else 0.0)
        )
        points.append((LAST_RUN, {'job': name}, state.last_started_at.timestamp() if state.last_started_at else 0.0))
        if state.last_duration_ms is not None:
            points.append((DURATION, {'job': name}, state.last_duration_ms / 1000.0))
        points.append((OVERDUE, {'job': name}, 1.0 if is_overdue(spec, state, now) else 0.0))
    points.append((SCHEDULER_ENABLED, {}, 1.0 if scheduler_enabled() else 0.0))
    reachable = redis_reachable()
    if reachable is not None:
        points.append((REDIS_UP, {}, 1.0 if reachable else 0.0))
        beat = beat_last_seen() if reachable else None
        if beat is not None:
            points.append((BEAT_LAST_SEEN, {}, beat.timestamp()))
    return points


def _cached_points() -> list[tuple[str, dict[str, str], float]]:
    now = time.monotonic()
    cached = _points_cache['points']
    if cached is not None and now - _points_cache['at'] < _CACHE_SECONDS:
        return cached
    points = scheduled_job_points()
    _points_cache['at'] = now
    _points_cache['points'] = points
    return points


def _callback(name: str):
    def callback(_options):
        from opentelemetry.metrics import Observation

        try:
            rows = [point for point in _cached_points() if point[0] == name]
        except Exception:
            logger.exception('scheduled job metric %s failed', name)
            return
        for _instrument, attributes, value in rows:
            yield Observation(value, attributes)

    return callback


def ensure_scheduled_job_metrics() -> None:
    """Register scheduled-job instruments. No effect when telemetry is off."""
    global _bound_generation
    from shellui_django.telemetry._state import state

    if not state.active or _bound_generation == state.generation:
        return
    meter = get_meter(_METER)
    if not hasattr(meter, 'create_observable_counter'):
        return
    meter.create_observable_counter(
        canonical_metric_name(RUNS),
        callbacks=[_callback(RUNS)],
        description='Finished scheduled job runs by status (succeeded, failed, skipped_locked).',
    )
    meter.create_observable_counter(
        canonical_metric_name(ITEMS),
        callbacks=[_callback(ITEMS)],
        description='Items processed by scheduled job runs, by kind.',
    )
    meter.create_observable_gauge(
        canonical_metric_name(LAST_SUCCESS),
        callbacks=[_callback(LAST_SUCCESS)],
        unit='s',
        description='Unix time when the last successful run finished (0 before the first one).',
    )
    meter.create_observable_gauge(
        canonical_metric_name(LAST_RUN),
        callbacks=[_callback(LAST_RUN)],
        unit='s',
        description='Unix time when the last run started (0 before the first one).',
    )
    meter.create_observable_gauge(
        canonical_metric_name(DURATION),
        callbacks=[_callback(DURATION)],
        unit='s',
        description='Duration of the last finished run.',
    )
    meter.create_observable_gauge(
        canonical_metric_name(OVERDUE),
        callbacks=[_callback(OVERDUE)],
        description='1 when the last successful run is older than 3 times the job interval.',
    )
    meter.create_observable_gauge(
        canonical_metric_name(SCHEDULER_ENABLED),
        callbacks=[_callback(SCHEDULER_ENABLED)],
        description='1 when the in-container Celery worker and beat run (SCHEDULER_ENABLED).',
    )
    meter.create_observable_gauge(
        canonical_metric_name(REDIS_UP),
        callbacks=[_callback(REDIS_UP)],
        description='1 when the scheduler broker (Redis) answers PING. Absent without a broker.',
    )
    meter.create_observable_gauge(
        canonical_metric_name(BEAT_LAST_SEEN),
        callbacks=[_callback(BEAT_LAST_SEEN)],
        unit='s',
        description='Unix time when Celery beat last published a scheduled job. Absent before the first one.',
    )
    _bound_generation = state.generation
