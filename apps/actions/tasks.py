"""
Celery tasks for the scheduled jobs.

Each task runs the existing management command, so cron users and the in-container
scheduler share one code path. A Redis lock (config.task_lock) makes sure only one
run of each job is active across all containers.
"""

import io
import logging

from celery import shared_task
from django.core.management import call_command

from config.task_lock import task_lock

logger = logging.getLogger(__name__)

# retry_webhooks stops after --max-seconds 50 (its default); the lock covers that plus
# in-flight HTTP calls. If a worker dies, retries resume after at most 2 minutes.
RETRY_WEBHOOKS_LOCK_TTL = 120

PURGE_EXPIRED_DATA_MAX_SECONDS = 300
# Purge stops after 300 seconds plus the batch in progress.
PURGE_EXPIRED_DATA_LOCK_TTL = 900


def _run_command(name: str, **options) -> str:
    out = io.StringIO()
    call_command(name, stdout=out, no_color=True, **options)
    summary = out.getvalue().strip()
    if summary:
        logger.info(summary)
    return summary


def _run_locked(name: str, ttl: int, **options) -> str:
    with task_lock(name, ttl=ttl) as acquired:
        if not acquired:
            logger.info('%s: skipped, another run is in progress', name)
            return 'skipped'
        return _run_command(name, **options)


@shared_task(name='actions.retry_webhooks', ignore_result=True)
def retry_webhooks() -> str:
    """Retry failed webhook deliveries and email-service event posts."""
    return _run_locked('retry_webhooks', ttl=RETRY_WEBHOOKS_LOCK_TTL)


@shared_task(name='actions.purge_expired_data', ignore_result=True)
def purge_expired_data() -> str:
    """Delete event log rows and finished deliveries past each company's retention."""
    return _run_locked(
        'purge_expired_data',
        ttl=PURGE_EXPIRED_DATA_LOCK_TTL,
        max_seconds=PURGE_EXPIRED_DATA_MAX_SECONDS,
    )
