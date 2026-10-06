"""Data retention: purge rows older than ``Company.data_retention_days`` and detect a missing purge job."""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timedelta

from django.db.models import Model, Q, QuerySet
from django.utils import timezone

from apps.actions.models import ActionOutbox, EmailEventOutbox, EventLog
from apps.companies.models import Company
from apps.scim.models import ScimProvisioningEvent

# Grace period before stale rows are reported: a purge job running at least daily never trips it.
STALE_GRACE = timedelta(days=1)

# Pending and failed deliveries are still retried, so only finished ones expire.
_FINISHED_DELIVERY = Q(status__in=(ActionOutbox.STATUS_DELIVERED, ActionOutbox.STATUS_DEAD))
_FINISHED_EMAIL = Q(status__in=(EmailEventOutbox.STATUS_DELIVERED, EmailEventOutbox.STATUS_DEAD))

# (label, model, extra filter, whether rows without a company exist)
_PURGE_TARGETS: tuple[tuple[str, type[Model], Q, bool], ...] = (
    ('events', EventLog, Q(), True),
    ('webhook_deliveries', ActionOutbox, _FINISHED_DELIVERY, False),
    ('email_events', EmailEventOutbox, _FINISHED_EMAIL, False),
    ('scim_provisioning_events', ScimProvisioningEvent, Q(), False),
)

# Bounds the IN (...) list when many companies share the same retention.
_COMPANY_CHUNK = 500


def retention_status(company: Company, *, now: datetime | None = None) -> dict:
    """
    Retention settings and health for ``company`` (one indexed query).

    ``stale_events`` is true when the oldest event is older than retention plus ``STALE_GRACE``,
    which means ``purge_expired_data`` is not scheduled or keeps failing.
    """
    now = now or timezone.now()
    days = company.data_retention_days
    oldest = (
        EventLog.objects.filter(company=company)
        .order_by('created_at')
        .values_list('created_at', flat=True)
        .first()
    )
    return {
        'data_retention_days': days,
        'oldest_event_at': oldest.isoformat() if oldest else None,
        'stale_events': bool(oldest and oldest < now - timedelta(days=days) - STALE_GRACE),
    }


def _delete_in_batches(qs: QuerySet, *, batch_size: int, deadline: float | None) -> tuple[int, bool]:
    """Delete ``qs`` in primary-key batches so each statement and lock stays short."""
    model = qs.model
    ids_qs = qs.order_by().values_list('pk', flat=True)
    deleted = 0
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            return deleted, False
        ids = list(ids_qs[:batch_size])
        if not ids:
            return deleted, True
        model.objects.filter(pk__in=ids).delete()
        deleted += len(ids)


def _expired_querysets(model: type[Model], extra: Q, has_null_company: bool, now: datetime):
    companies_by_days: dict[int, list[int]] = defaultdict(list)
    for company_id, days in Company.objects.values_list('id', 'data_retention_days'):
        companies_by_days[days].append(company_id)
    for days, company_ids in sorted(companies_by_days.items()):
        cutoff = now - timedelta(days=days)
        for start in range(0, len(company_ids), _COMPANY_CHUNK):
            chunk = company_ids[start : start + _COMPANY_CHUNK]
            yield model.objects.filter(extra, company_id__in=chunk, created_at__lt=cutoff)
    if has_null_company:
        cutoff = now - timedelta(days=Company.DEFAULT_DATA_RETENTION_DAYS)
        yield model.objects.filter(extra, company__isnull=True, created_at__lt=cutoff)


def purge_expired_data(
    *,
    batch_size: int = 2000,
    max_seconds: float | None = None,
    dry_run: bool = False,
    now: datetime | None = None,
) -> dict:
    """
    Delete expired event log rows, finished webhook deliveries and SCIM provisioning events.

    Rows without a company (sign-in failures before the company is known) use
    ``Company.DEFAULT_DATA_RETENTION_DAYS``. Returns per-target counts and ``complete=False``
    when ``max_seconds`` ran out first (the next run picks up where this one stopped).
    """
    now = now or timezone.now()
    deadline = time.monotonic() + max_seconds if max_seconds else None
    stats: dict = {label: 0 for label, *_ in _PURGE_TARGETS}
    stats['complete'] = True
    for label, model, extra, has_null_company in _PURGE_TARGETS:
        for qs in _expired_querysets(model, extra, has_null_company, now):
            if dry_run:
                stats[label] += qs.count()
                continue
            deleted, finished = _delete_in_batches(qs, batch_size=batch_size, deadline=deadline)
            stats[label] += deleted
            if not finished:
                stats['complete'] = False
                return stats
    return stats
