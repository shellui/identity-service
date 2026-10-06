"""
Celery app for the scheduled jobs (``retry_webhooks`` and ``purge_expired_data``).

The Docker entrypoint starts a worker with an embedded beat next to gunicorn, so a
self-hosted install needs no cron setup. Redis (``REDIS_URL``) is the broker.
See docs/scheduled-jobs.md.

This module only depends on Django settings named ``CELERY_*`` and
``SCHEDULER_LOCK_PREFIX``, so it can be copied as-is to the other Shellui services.
"""

import os

from celery import Celery
from celery.signals import setup_logging

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('config')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


@setup_logging.connect
def _use_django_logging(**kwargs):
    """
    Keep Django's LOGGING (stdout, LOG_LEVEL, request id) in the worker.

    Without a receiver, Celery replaces the root logger level with its own --loglevel.
    """
    import logging.config

    from django.conf import settings

    logging.config.dictConfig(settings.LOGGING)
