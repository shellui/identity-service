"""Celery task: purge companies flagged for deletion (every 60 seconds, see settings)."""

import logging

from celery import shared_task

from config.task_lock import task_lock

logger = logging.getLogger(__name__)

PURGE_DELETED_COMPANIES_LOCK_TTL = 120


@shared_task(name='companies.purge_deleted_companies', ignore_result=True)
def purge_deleted_companies() -> str:
    from apps.companies.deletion import purge_deleted_companies as run

    with task_lock('purge_deleted_companies', ttl=PURGE_DELETED_COMPANIES_LOCK_TTL) as acquired:
        if not acquired:
            return 'skipped'
        summary = 'purge_deleted_companies: ' + ' '.join(f'{k}={v}' for k, v in run().items())
        logger.info(summary)
        return summary
