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
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Delivery attempt'
        verbose_name_plural = 'Delivery attempts'
        ordering = ['-created_at']

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
