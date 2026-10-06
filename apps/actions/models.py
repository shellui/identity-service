from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.actions.registry import event_choices


def _event_type_field_choices():
    # Side-effect import: register identity.* events if this runs before AppConfig.ready().
    from apps.actions import identity_events  # noqa: F401

    return event_choices()


class ActionRule(models.Model):
    ACTION_WEBHOOK = 'webhook'
    ACTION_KIND_CHOICES = [
        (ACTION_WEBHOOK, 'Webhook'),
    ]

    company = models.ForeignKey(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='action_rules',
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    event_type = models.CharField(max_length=128, choices=_event_type_field_choices)
    enabled = models.BooleanField(default=True)
    action_kind = models.CharField(
        max_length=16,
        choices=ACTION_KIND_CHOICES,
        default=ACTION_WEBHOOK,
    )
    config = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['company_id', 'event_type', 'name']
        indexes = [
            models.Index(fields=['company', 'event_type', 'enabled']),
        ]

    def __str__(self) -> str:
        return f'{self.company.slug}:{self.event_type}:{self.name}'


class ActionOutbox(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_DELIVERED = 'delivered'
    STATUS_FAILED = 'failed'
    STATUS_DEAD = 'dead'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_DELIVERED, 'Delivered'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_DEAD, 'Dead'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='action_outbox_rows',
    )
    action_rule = models.ForeignKey(
        ActionRule,
        on_delete=models.CASCADE,
        related_name='outbox_rows',
    )
    event_type = models.CharField(max_length=128)
    envelope = models.JSONField()
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
    )
    attempt_count = models.PositiveIntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True, db_index=True)
    locked_until = models.DateTimeField(null=True, blank=True, db_index=True)
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'Action delivery'
        verbose_name_plural = 'Action deliveries'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'next_attempt_at']),
        ]

    def __str__(self) -> str:
        return f'{self.event_type} → rule {self.action_rule_id} ({self.status})'


class DeliveryAttempt(models.Model):
    STATUS_SUCCESS = 'success'
    STATUS_FAILURE = 'failure'
    STATUS_CHOICES = [
        (STATUS_SUCCESS, 'Success'),
        (STATUS_FAILURE, 'Failure'),
    ]

    TRIGGER_DISPATCH = 'dispatch'
    TRIGGER_AUTOMATIC_RETRY = 'automatic_retry'
    TRIGGER_CHOICES = [
        (TRIGGER_DISPATCH, 'Dispatch'),
        (TRIGGER_AUTOMATIC_RETRY, 'Automatic retry'),
    ]

    outbox = models.ForeignKey(
        ActionOutbox,
        on_delete=models.CASCADE,
        related_name='delivery_attempts',
    )
    status = models.CharField(max_length=16, choices=STATUS_CHOICES)
    http_status = models.PositiveIntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    attempt_number = models.PositiveIntegerField()
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    # ``dispatch``: first try right after the event. ``automatic_retry``: retry_webhooks job.
    # Empty for attempts recorded before 0.7.0.
    trigger = models.CharField(max_length=16, choices=TRIGGER_CHOICES, blank=True)
    # ``ScheduledJobRun`` that made this attempt (staff only in the API; no FK, runs are purged first).
    scheduled_job_run_id = models.BigIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Delivery attempt'
        verbose_name_plural = 'Delivery attempts'
        ordering = ['-created_at']
        indexes = [
            models.Index(
                fields=['scheduled_job_run_id'],
                name='actions_attempt_sjrun_idx',
                condition=models.Q(scheduled_job_run_id__isnull=False),
            ),
        ]

    def __str__(self) -> str:
        return f'attempt {self.attempt_number} ({self.status})'


class EventLog(models.Model):
    """
    Append-only history of every catalog event (webhook events and sign-ins), one row per event.

    Rows are deleted by ``manage.py purge_expired_data`` after ``Company.data_retention_days``.
    ``data`` is the event payload without empty values, ``user_id`` (stored in ``user``) or
    the event type's ``sensitive_fields``. The two composite indexes cover every read path
    (company timeline, user timeline, retention purge), so the foreign keys carry no index of their own.
    """

    id = models.BigAutoField(primary_key=True)
    company = models.ForeignKey(
        'companies.Company',
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        db_index=False,
        related_name='+',
    )
    # No DB constraint: inserts skip the users lookup; Django still nulls it when the user is deleted.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        db_index=False,
        db_constraint=False,
        related_name='+',
    )
    event_type = models.CharField(max_length=64)
    data = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = 'Event log entry'
        verbose_name_plural = 'Event log'
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['company', '-created_at'], name='actions_eventlog_company_idx'),
            models.Index(fields=['user', '-created_at'], name='actions_eventlog_user_idx'),
        ]

    def __str__(self) -> str:
        return f'{self.event_type} ({self.created_at:%Y-%m-%d %H:%M})'


class EmailEventOutbox(models.Model):
    """
    DB outbox for ``POST /api/v1/events`` on Shellui email-service.

    Same retry shape as webhook deliveries: ``retry_webhooks`` claims pending and failed rows.
    The request path only inserts a row. It does not call email-service.
    """

    STATUS_PENDING = 'pending'
    STATUS_DELIVERED = 'delivered'
    STATUS_FAILED = 'failed'
    STATUS_DEAD = 'dead'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_DELIVERED, 'Delivered'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_DEAD, 'Dead'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='email_event_outbox_rows',
    )
    event_type = models.CharField(max_length=128)
    idempotency_key = models.CharField(max_length=200, unique=True)
    body = models.JSONField()
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
    )
    attempt_count = models.PositiveIntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True, db_index=True)
    locked_until = models.DateTimeField(null=True, blank=True, db_index=True)
    last_error = models.TextField(blank=True)
    # Who made the last attempt: ``dispatch`` (right after the event) or ``automatic_retry``.
    last_trigger = models.CharField(max_length=16, blank=True)
    # ``ScheduledJobRun`` of the last attempt. The attempt that delivered the email keeps it.
    last_scheduled_job_run_id = models.BigIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'Email event delivery'
        verbose_name_plural = 'Email event deliveries'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'next_attempt_at']),
            models.Index(
                fields=['last_scheduled_job_run_id'],
                name='actions_emailev_sjrun_idx',
                condition=models.Q(last_scheduled_job_run_id__isnull=False),
            ),
        ]

    def __str__(self) -> str:
        return f'{self.event_type} ({self.status})'


class ScheduledJobRun(models.Model):
    """
    One run of a scheduled job (``retry_webhooks``, ``purge_expired_data``).

    Written by the management command itself, so runs started by the in-container Celery
    beat and by an external cron are both recorded. Skipped runs (another run held the
    lock) are not stored: they only increment a counter (see ``ScheduledJobCounter``).
    ``purge_expired_data`` deletes rows older than ``scheduled_jobs.RUN_RETENTION_DAYS``.
    """

    TRIGGER_CELERY = 'celery'
    TRIGGER_COMMAND = 'command'
    TRIGGER_CHOICES = [
        (TRIGGER_CELERY, 'Celery beat'),
        (TRIGGER_COMMAND, 'Management command'),
    ]

    STATUS_RUNNING = 'running'
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_FAILED = 'failed'
    STATUS_SKIPPED_LOCKED = 'skipped_locked'
    STATUS_CHOICES = [
        (STATUS_RUNNING, 'Running'),
        (STATUS_SUCCEEDED, 'Succeeded'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_SKIPPED_LOCKED, 'Skipped (lock held)'),
    ]

    id = models.BigAutoField(primary_key=True)
    job = models.CharField(max_length=64)
    trigger = models.CharField(max_length=16, choices=TRIGGER_CHOICES)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_RUNNING)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    # Integer counters per item kind, for example ``webhook_deliveries_succeeded``.
    counts = models.JSONField(default=dict, blank=True)
    # Stable key the admin panel translates (``database_error``, ``redis_error``, …).
    error_key = models.CharField(max_length=32, blank=True)
    error_class = models.CharField(max_length=128, blank=True)
    # Sanitized and truncated: no URL query strings, credentials or tokens.
    error_message = models.CharField(max_length=300, blank=True)
    host = models.CharField(max_length=128, blank=True)
    # Staff-only platform event written when the run finished (no FK: purged separately).
    event_log_id = models.BigIntegerField(null=True, blank=True)

    class Meta:
        verbose_name = 'Scheduled job run'
        verbose_name_plural = 'Scheduled job runs'
        ordering = ['-started_at', '-id']
        indexes = [
            models.Index(fields=['job', '-started_at'], name='actions_sjrun_job_idx'),
            models.Index(fields=['started_at'], name='actions_sjrun_started_idx'),
        ]

    def __str__(self) -> str:
        return f'{self.job} #{self.pk} ({self.status})'

    @property
    def request_id(self) -> str:
        """Log correlation id used while the run executes (``[req=…]`` in log lines)."""
        return f'sjr-{self.pk}'


class ScheduledJobState(models.Model):
    """Latest timestamps per job. Survives run retention, so ``last_success_at`` is never lost."""

    job = models.CharField(max_length=64, primary_key=True)
    # Creation time is the reference for ``overdue`` until the first successful run.
    created_at = models.DateTimeField(default=timezone.now)
    last_started_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_failure_at = models.DateTimeField(null=True, blank=True)
    last_skipped_at = models.DateTimeField(null=True, blank=True)
    last_duration_ms = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        verbose_name = 'Scheduled job state'
        verbose_name_plural = 'Scheduled job states'

    def __str__(self) -> str:
        return self.job


class ScheduledJobCounter(models.Model):
    """
    Monotonic counters for Prometheus (``runs.<status>``, ``items.<kind>``).

    Stored in the database because runs happen in the Celery worker or a cron process,
    while ``/api/v1/metrics/all`` is served by gunicorn workers.
    """

    job = models.CharField(max_length=64)
    name = models.CharField(max_length=64)
    value = models.BigIntegerField(default=0)

    class Meta:
        verbose_name = 'Scheduled job counter'
        verbose_name_plural = 'Scheduled job counters'
        constraints = [
            models.UniqueConstraint(fields=['job', 'name'], name='actions_sjcounter_job_name_uniq'),
        ]

    def __str__(self) -> str:
        return f'{self.job}:{self.name}={self.value}'
