"""Forward webhook catalog events to email-service ``POST /api/v1/events``.

Rows are inserted on the request path and delivered after commit, then retried by
``manage.py retry_webhooks``. Magic-link and invitation mail use ``POST /api/v1/send``
instead: those catalog rules are on by default, so posting them here as well would
send a second message.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection, transaction
from django.db.models import Q
from django.utils import timezone

from apps.actions.email_client import (
    DIRECT_SEND_EVENT_TYPES,
    SERVICE_NAME,
    EmailServiceRejected,
    EmailServiceUnreachable,
    email_service_configured,
    post_event,
)
from apps.actions.models import EmailEventOutbox
from apps.actions.registry import DomainEventType
from apps.actions.webhook_retry import compute_retry_delay_seconds
from apps.authapi.magic_link import normalize_magic_link_language

logger = logging.getLogger(__name__)

_EXECUTOR: ThreadPoolExecutor | None = None
_MAX_RECIPIENTS = 50

# Identity webhook payloads use ``name``. The email template token is ``token_name``.
_TOKEN_NAME_EVENTS = frozenset({
    'identity.scim.token.created',
    'identity.scim.token.revoked',
})


def _executor() -> ThreadPoolExecutor:
    global _EXECUTOR
    if _EXECUTOR is None:
        workers = int(getattr(settings, 'ACTIONS_WEBHOOK_DISPATCH_WORKERS', 4) or 4)
        _EXECUTOR = ThreadPoolExecutor(
            max_workers=max(1, workers),
            thread_name_prefix='email-event',
        )
    return _EXECUTOR


def _max_attempts() -> int:
    return int(getattr(settings, 'ACTIONS_OUTBOX_MAX_ATTEMPTS', 8) or 8)


def _backoff_seconds(attempt_number: int) -> int:
    return min(3600, 30 * (2 ** max(0, attempt_number - 1)))


def _lease_seconds() -> int:
    return int(getattr(settings, 'ACTIONS_WEBHOOK_RETRY_LEASE_SECONDS', 120) or 120)


def _recipient_hints(company, payload: dict) -> list[dict]:
    email = str(payload.get('email') or '').strip()
    if email:
        hint: dict = {'email': email}
        user_id = payload.get('user_id')
        if isinstance(user_id, int) and not isinstance(user_id, bool):
            hint['user_id'] = user_id
        return [hint]

    hints: list[dict] = []
    seen: set[str] = set()

    def add(addr: str, user_id: int | None) -> None:
        cleaned = (addr or '').strip()
        key = cleaned.lower()
        if not cleaned or key in seen or len(hints) >= _MAX_RECIPIENTS:
            return
        seen.add(key)
        item = {'email': cleaned}
        if user_id is not None:
            item['user_id'] = user_id
        hints.append(item)

    for owner in company.owners.all().only('id', 'email'):
        add(owner.email, owner.pk)
    if hints:
        return hints
    User = get_user_model()
    for staff in User.objects.filter(is_staff=True).only('id', 'email'):
        add(staff.email, staff.pk)
        if len(hints) >= _MAX_RECIPIENTS:
            break
    return hints


def _event_payload(event: DomainEventType, company, payload: dict) -> dict:
    data: dict = {'company_name': company.name}
    if event.id in _TOKEN_NAME_EVENTS and payload.get('name'):
        data['token_name'] = payload['name']
    skip = {'user_id', 'email', 'username', 'region', 'language', 'name', *event.sensitive_fields}
    for key, value in payload.items():
        if key in skip or value in (None, '', [], {}):
            continue
        data[key] = value
    return data


def build_event_body(event: DomainEventType, company, payload: dict, *, event_log_id: int) -> dict | None:
    """JSON body for ``POST /api/v1/events``, or None when this event must not be forwarded."""
    if not event.webhook or event.id in DIRECT_SEND_EVENT_TYPES:
        return None
    recipients = _recipient_hints(company, payload)
    if not recipients:
        return None
    body = {
        'service': SERVICE_NAME,
        'event_type': event.id,
        'company_id': company.pk,
        'idempotency_key': f'identity-event-{event_log_id}',
        'payload': _event_payload(event, company, payload),
        'recipients': recipients,
    }
    language = normalize_magic_link_language(payload.get('language') if isinstance(payload, dict) else None)
    if language:
        body['language'] = language
    return body


def enqueue_email_event(event: DomainEventType, company, payload: dict, *, event_log_id: int) -> EmailEventOutbox | None:
    """Insert one outbox row when email-service is configured. Never raises."""
    if not email_service_configured():
        return None
    try:
        body = build_event_body(event, company, payload, event_log_id=event_log_id)
        if body is None:
            if event.webhook and event.id not in DIRECT_SEND_EVENT_TYPES:
                logger.info(
                    'email_event_skipped company_id=%s event_type=%s reason=no_recipients',
                    company.pk,
                    event.id,
                )
            return None
        row = EmailEventOutbox.objects.create(
            company=company,
            event_type=event.id,
            idempotency_key=body['idempotency_key'],
            body=body,
        )
    except Exception as exc:
        logger.warning(
            'email_event_enqueue_failed company_id=%s event_type=%s error=%s',
            getattr(company, 'pk', None),
            getattr(event, 'id', ''),
            exc.__class__.__name__,
        )
        return None
    schedule_email_event_delivery(row.pk)
    return row


def schedule_email_event_delivery(row_id) -> None:
    def _run() -> None:
        if getattr(settings, 'ACTIONS_WEBHOOK_SYNC_DELIVERY', False):
            _safe_deliver(row_id)
            return
        _executor().submit(_safe_deliver, row_id)

    transaction.on_commit(_run)


def _safe_deliver(row_id) -> None:
    connection.close()
    try:
        deliver_email_event(row_id)
    except Exception as exc:
        logger.warning('email_event_delivery_error outbox_id=%s error=%s', row_id, exc.__class__.__name__)


def _apply_result(row: EmailEventOutbox, *, success: bool, permanent: bool, error: str, http_status: int | None, retry_after: int | None) -> EmailEventOutbox:
    attempt_number = row.attempt_count + 1
    row.attempt_count = attempt_number
    row.locked_until = None
    if success:
        row.status = EmailEventOutbox.STATUS_DELIVERED
        row.delivered_at = timezone.now()
        row.last_error = ''
        row.next_attempt_at = None
    elif permanent or attempt_number >= _max_attempts():
        row.status = EmailEventOutbox.STATUS_DEAD
        row.last_error = error
        row.next_attempt_at = None
    else:
        row.status = EmailEventOutbox.STATUS_FAILED
        row.last_error = error
        delay = compute_retry_delay_seconds(
            attempt_number=attempt_number,
            http_status=http_status,
            retry_after_seconds=retry_after,
            base_backoff_seconds=_backoff_seconds(attempt_number),
        )
        row.next_attempt_at = timezone.now() + timedelta(seconds=delay)
    row.save(
        update_fields=[
            'status',
            'attempt_count',
            'last_error',
            'next_attempt_at',
            'delivered_at',
            'locked_until',
            'updated_at',
        ]
    )
    logger.info(
        'email_event_delivery outbox_id=%s attempt=%s success=%s http_status=%s',
        row.pk,
        attempt_number,
        success,
        http_status,
    )
    return row


def deliver_email_event(row_id) -> EmailEventOutbox | None:
    with transaction.atomic():
        row = (
            EmailEventOutbox.objects.select_for_update()
            .filter(pk=row_id)
            .first()
        )
        if row is None or row.status in {EmailEventOutbox.STATUS_DELIVERED, EmailEventOutbox.STATUS_DEAD}:
            return row
        body = row.body
        snapshot = row.attempt_count
        if not email_service_configured():
            return _apply_result(
                row,
                success=False,
                permanent=True,
                error='email_service_unconfigured',
                http_status=None,
                retry_after=None,
            )

    success = False
    permanent = False
    error = ''
    http_status = None
    retry_after = None
    try:
        post_event(body)
        success = True
    except EmailServiceRejected as exc:
        permanent = not exc.retryable
        http_status = exc.status
        error = exc.error_code
        retry_after = exc.retry_after
    except EmailServiceUnreachable as exc:
        error = exc.error_code or 'unreachable'
        http_status = exc.status
        retry_after = exc.retry_after
    except Exception as exc:
        logger.warning('email_event_post_failed outbox_id=%s error=%s', row_id, exc.__class__.__name__)
        error = 'request_failed'

    with transaction.atomic():
        row = EmailEventOutbox.objects.select_for_update().get(pk=row_id)
        if row.attempt_count != snapshot or row.status in {
            EmailEventOutbox.STATUS_DELIVERED,
            EmailEventOutbox.STATUS_DEAD,
        }:
            return row
        return _apply_result(
            row,
            success=success,
            permanent=permanent,
            error=error,
            http_status=http_status,
            retry_after=retry_after,
        )


def claim_next_pending_email_event(*, now=None) -> EmailEventOutbox | None:
    now = now or timezone.now()
    lease_until = now + timedelta(seconds=_lease_seconds())
    with transaction.atomic():
        row = (
            EmailEventOutbox.objects.filter(
                status__in=[EmailEventOutbox.STATUS_PENDING, EmailEventOutbox.STATUS_FAILED],
            )
            .filter(Q(next_attempt_at__isnull=True) | Q(next_attempt_at__lte=now))
            .filter(Q(locked_until__isnull=True) | Q(locked_until__lte=now))
            .select_for_update(skip_locked=True)
            .order_by('next_attempt_at', 'created_at')
            .first()
        )
        if row is None:
            return None
        row.locked_until = lease_until
        row.save(update_fields=['locked_until', 'updated_at'])
        return row


def retry_pending_email_events(
    *,
    batch_size: int = 50,
    max_seconds: float = 50.0,
    dry_run: bool = False,
    now=None,
) -> dict[str, int]:
    """Retry email-service event posts. Same cron entry as webhook deliveries."""
    import time

    now = now or timezone.now()
    stats = {'processed': 0, 'delivered': 0, 'retried': 0, 'dead': 0}
    deadline = time.monotonic() + max(0.1, float(max_seconds))
    while stats['processed'] < batch_size and time.monotonic() < deadline:
        row = claim_next_pending_email_event(now=now)
        if row is None:
            break
        before = row.status
        if dry_run:
            stats['processed'] += 1
            EmailEventOutbox.objects.filter(pk=row.pk).update(locked_until=None)
            continue
        after = deliver_email_event(row.pk)
        stats['processed'] += 1
        if after is None:
            continue
        if after.status == EmailEventOutbox.STATUS_DELIVERED:
            stats['delivered'] += 1
        elif after.status == EmailEventOutbox.STATUS_DEAD:
            stats['dead'] += 1
        elif after.status == EmailEventOutbox.STATUS_FAILED or before in {
            EmailEventOutbox.STATUS_PENDING,
            EmailEventOutbox.STATUS_FAILED,
        }:
            stats['retried'] += 1
    return stats
