"""OpenTelemetry metrics for identity-service.

Gauges are read from the database when the SDK collects them. The login counter
is per process, same as the old Prometheus counter, and carries ``company_id``
and ``provider``. There is no scrape endpoint.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.utils import timezone
from shellui_django.telemetry import canonical_metric_name, counter, get_meter

from apps.companies.models import Company, CompanyMembership

from .models import UserActivity

logger = logging.getLogger(__name__)

_METER = 'shellui.identity'
_CACHE_SECONDS = 1.0
_bound_generation = -1
_snapshot_cache: dict = {'at': 0.0, 'platform': None, 'companies': None}

_successful_logins = counter(
    'shellui_auth_successful_logins_total',
    description='Successful sign-ins since this process started (browser callback or API login).',
    meter_name=_METER,
)
_login_counts_lock = threading.Lock()
_login_counts: dict[tuple[int, str], int] = {}

_PLATFORM_GAUGES: tuple[tuple[str, str], ...] = (
    ('shellui_auth_users_total', 'Number of Django user rows.'),
    ('shellui_auth_users_active', 'Users with is_active=True.'),
    ('shellui_auth_users_staff', 'Users with is_staff=True.'),
    ('shellui_auth_social_accounts_total', 'Linked OAuth social account rows (django-allauth SocialAccount).'),
    (
        'shellui_auth_daily_active_users',
        'Users with last_seen_at on or after midnight at the start of the current calendar day.',
    ),
    (
        'shellui_auth_weekly_active_users',
        'Users with last_seen_at on or after Monday 00:00 of the current ISO calendar week.',
    ),
    (
        'shellui_auth_monthly_active_users',
        'Users with last_seen_at in the current calendar month.',
    ),
)

_COMPANY_GAUGES: tuple[tuple[str, str], ...] = (
    ('shellui_auth_company_users_total', 'Number of users in a company.'),
    ('shellui_auth_company_users_active', 'Number of users with company membership is_enabled=True.'),
    ('shellui_auth_company_users_staff', 'Number of staff users in a company.'),
    ('shellui_auth_company_social_accounts_total', 'Linked social account rows for company users.'),
    ('shellui_auth_company_daily_active_users', 'Company users active today.'),
    ('shellui_auth_company_weekly_active_users', 'Company users active this ISO week.'),
    ('shellui_auth_company_monthly_active_users', 'Company users active this month.'),
)


def _count_user_activity_since(cutoff) -> int:
    return UserActivity.objects.filter(last_seen_at__gte=cutoff).count()


def _count_company_user_activity_since(company: Company, cutoff) -> int:
    return UserActivity.objects.filter(user__companies=company, last_seen_at__gte=cutoff).distinct().count()


def _activity_cutoffs():
    now = timezone.now()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return day_start, week_start, month_start


def platform_gauge_values() -> dict[str, int]:
    """Current platform-wide user gauges."""
    User = get_user_model()
    day_start, week_start, month_start = _activity_cutoffs()
    return {
        'shellui_auth_users_total': User.objects.count(),
        'shellui_auth_users_active': User.objects.filter(is_active=True).count(),
        'shellui_auth_users_staff': User.objects.filter(is_staff=True).count(),
        'shellui_auth_social_accounts_total': SocialAccount.objects.count(),
        'shellui_auth_daily_active_users': _count_user_activity_since(day_start),
        'shellui_auth_weekly_active_users': _count_user_activity_since(week_start),
        'shellui_auth_monthly_active_users': _count_user_activity_since(month_start),
    }


def company_gauge_values(company: Company) -> dict[str, int]:
    """Current value of each company gauge for one company."""
    users = get_user_model().objects.filter(companies=company).distinct()
    day_start, week_start, month_start = _activity_cutoffs()
    return {
        'shellui_auth_company_users_total': users.count(),
        'shellui_auth_company_users_active': CompanyMembership.objects.filter(
            company=company, is_enabled=True
        ).count(),
        'shellui_auth_company_users_staff': users.filter(is_staff=True).count(),
        'shellui_auth_company_social_accounts_total': SocialAccount.objects.filter(user__companies=company)
        .distinct()
        .count(),
        'shellui_auth_company_daily_active_users': _count_company_user_activity_since(company, day_start),
        'shellui_auth_company_weekly_active_users': _count_company_user_activity_since(company, week_start),
        'shellui_auth_company_monthly_active_users': _count_company_user_activity_since(company, month_start),
    }


def _cached_snapshots() -> tuple[dict[str, int], list[tuple[str, dict[str, int]]]]:
    now = time.monotonic()
    if _snapshot_cache['platform'] is not None and now - _snapshot_cache['at'] < _CACHE_SECONDS:
        return _snapshot_cache['platform'], _snapshot_cache['companies']
    platform = platform_gauge_values()
    companies = [(str(company.pk), company_gauge_values(company)) for company in list(Company.objects.all())]
    _snapshot_cache['at'] = now
    _snapshot_cache['platform'] = platform
    _snapshot_cache['companies'] = companies
    return platform, companies


def record_successful_login(provider: str, company_id: int) -> None:
    name = (provider or 'unknown').strip().lower() or 'unknown'
    _successful_logins.add(1, {'provider': name, 'company_id': str(company_id)})
    with _login_counts_lock:
        key = (int(company_id), name)
        _login_counts[key] = _login_counts.get(key, 0) + 1


def company_successful_logins(company_id: int) -> list[dict[str, int | str]]:
    """Per-process successful sign-ins for one company since process start."""
    cid = int(company_id)
    with _login_counts_lock:
        rows = [
            {'provider': provider, 'total': total}
            for (row_cid, provider), total in _login_counts.items()
            if row_cid == cid and total > 0
        ]
    rows.sort(key=lambda row: (-int(row['total']), str(row['provider'])))
    return rows


def company_stats_snapshot(company: Company) -> dict:
    """Company-scoped JSON statistics for the admin dashboard and identity stats page."""
    values = company_gauge_values(company)
    return {
        'company_id': company.id,
        'users_total': values['shellui_auth_company_users_total'],
        'users_active': values['shellui_auth_company_users_active'],
        'users_staff': values['shellui_auth_company_users_staff'],
        'social_accounts_total': values['shellui_auth_company_social_accounts_total'],
        'daily_active_users': values['shellui_auth_company_daily_active_users'],
        'weekly_active_users': values['shellui_auth_company_weekly_active_users'],
        'monthly_active_users': values['shellui_auth_company_monthly_active_users'],
        'successful_logins': company_successful_logins(company.id),
    }


def _reset_login_counts_for_tests() -> None:
    with _login_counts_lock:
        _login_counts.clear()


def _observe(reader):
    def callback(_options):
        from opentelemetry.metrics import Observation

        try:
            result = reader()
        except Exception:
            logger.exception('identity metric callback failed')
            return
        if result is None:
            return
        if isinstance(result, list):
            for value, attributes in result:
                yield Observation(value, attributes)
            return
        yield Observation(result)

    return callback


def ensure_auth_metrics() -> None:
    """Register observable gauges on the active meter. No effect when telemetry is off."""
    global _bound_generation
    from shellui_django.telemetry._state import state

    if not state.active or _bound_generation == state.generation:
        return
    meter = get_meter(_METER)
    if not hasattr(meter, 'create_observable_gauge'):
        return

    def platform_reader(key: str):
        def read():
            platform, _companies = _cached_snapshots()
            return platform[key]

        return read

    for key, description in _PLATFORM_GAUGES:
        meter.create_observable_gauge(
            canonical_metric_name(key),
            callbacks=[_observe(platform_reader(key))],
            description=description,
        )

    def company_reader(key: str):
        def read():
            _platform, companies = _cached_snapshots()
            return [(values[key], {'company_id': company_id}) for company_id, values in companies]

        return read

    for key, description in _COMPANY_GAUGES:
        meter.create_observable_gauge(
            canonical_metric_name(key),
            callbacks=[_observe(company_reader(key))],
            description=description,
        )
    _bound_generation = state.generation
