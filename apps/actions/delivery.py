"""Outbox delivery, retries, and post-commit dispatch."""

from __future__ import annotations

import logging
import time
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.actions.handlers.email import deliver_email_action
from apps.actions.handlers.webhook import deliver_webhook_action
from apps.actions.handlers.webhook import WebhookDeliveryError
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt

logger = logging.getLogger(__name__)


def _max_attempts() -> int:
    return int(getattr(settings, 'ACTIONS_OUTBOX_MAX_ATTEMPTS', 5))


def _backoff_seconds(attempt_number: int) -> int:
    return min(3600, 30 * (2 ** max(0, attempt_number - 1)))


def _deliver_for_rule(*, rule: ActionRule, envelope: dict) -> None:
    if rule.action_kind == ActionRule.ACTION_EMAIL:
        deliver_email_action(config=rule.config or {}, envelope=envelope)
        return
    if rule.action_kind == ActionRule.ACTION_WEBHOOK:
        deliver_webhook_action(config=rule.config or {}, envelope=envelope)
        return
    raise ValueError(f'Unsupported action kind: {rule.action_kind!r}')


def _deliver_outbox_row(row: ActionOutbox) -> ActionOutbox:
    if row.status == ActionOutbox.STATUS_DELIVERED:
        return row
    if row.status == ActionOutbox.STATUS_DEAD:
        return row

    rule = row.action_rule
    if not rule.enabled:
        row.status = ActionOutbox.STATUS_DEAD
        row.last_error = 'Action rule disabled.'
        row.save(update_fields=['status', 'last_error', 'updated_at'])
        return row

    attempt_number = row.attempt_count + 1
    started = time.monotonic()
    http_status = None
    error_message = ''
    success = False
    try:
        _deliver_for_rule(rule=rule, envelope=row.envelope)
        success = True
    except WebhookDeliveryError as exc:
        error_message = str(exc)
        http_status = exc.http_status
    except Exception as exc:  # noqa: BLE001 — record and retry delivery failures
        error_message = str(exc) or exc.__class__.__name__
        logger.exception('Action delivery failed outbox_id=%s', row.pk)

    duration_ms = int((time.monotonic() - started) * 1000)
    DeliveryAttempt.objects.create(
        outbox=row,
        status=DeliveryAttempt.STATUS_SUCCESS if success else DeliveryAttempt.STATUS_FAILURE,
        http_status=http_status,
        error_message=error_message,
        attempt_number=attempt_number,
        duration_ms=duration_ms,
    )

    row.attempt_count = attempt_number
    if success:
        row.status = ActionOutbox.STATUS_DELIVERED
        row.delivered_at = timezone.now()
        row.last_error = ''
        row.next_attempt_at = None
    elif attempt_number >= _max_attempts():
        row.status = ActionOutbox.STATUS_DEAD
        row.last_error = error_message
        row.next_attempt_at = None
    else:
        row.status = ActionOutbox.STATUS_FAILED
        row.last_error = error_message
        row.next_attempt_at = timezone.now() + timedelta(seconds=_backoff_seconds(attempt_number))
    row.save(
        update_fields=[
            'status',
            'attempt_count',
            'last_error',
            'next_attempt_at',
            'delivered_at',
            'updated_at',
        ]
    )
    return row


def deliver_outbox_row(outbox_id) -> ActionOutbox | None:
    with transaction.atomic():
        row = (
            ActionOutbox.objects.select_for_update()
            .select_related('action_rule', 'company')
            .filter(pk=outbox_id)
            .first()
        )
        if row is None:
            return None
        return _deliver_outbox_row(row)


def schedule_outbox_delivery(outbox_ids: list) -> None:
    def _run() -> None:
        for oid in outbox_ids:
            try:
                deliver_outbox_row(oid)
            except Exception:  # noqa: BLE001
                logger.exception('Post-commit action delivery error outbox_id=%s', oid)

    transaction.on_commit(_run)


def _pending_outbox_filter(now):
    return (
        ActionOutbox.objects.filter(
            status__in=[ActionOutbox.STATUS_PENDING, ActionOutbox.STATUS_FAILED],
        )
        .filter(Q(next_attempt_at__isnull=True) | Q(next_attempt_at__lte=now))
    )


def drain_pending_outbox(*, batch_size: int = 50, now=None) -> int:
    now = now or timezone.now()
    count = 0
    for _ in range(max(1, batch_size)):
        with transaction.atomic():
            row = (
                _pending_outbox_filter(now)
                .select_for_update(skip_locked=True)
                .select_related('action_rule', 'company')
                .order_by('created_at')
                .first()
            )
            if row is None:
                break
            _deliver_outbox_row(row)
        count += 1
    return count
