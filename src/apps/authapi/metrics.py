"""Prometheus-style metrics for shellui-auth; exposition is staff JWT–protected (see ShellUIAdminMetricsView)."""

from __future__ import annotations

from datetime import timedelta

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.utils import timezone
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

from .models import UserActivity

_users_total = Gauge(
    'shellui_auth_users_total',
    'Number of Django user rows.',
)
_users_active = Gauge(
    'shellui_auth_users_active',
    'Users with is_active=True.',
)
_users_staff = Gauge(
    'shellui_auth_users_staff',
    'Users with is_staff=True.',
)
_social_accounts_total = Gauge(
    'shellui_auth_social_accounts_total',
    'Linked OAuth social account rows (django-allauth SocialAccount).',
)
_daily_active_users = Gauge(
    'shellui_auth_daily_active_users',
    'Users with last_seen_at on or after midnight at the start of the current calendar day (same tz as timezone.now()).',
)
_weekly_active_users = Gauge(
    'shellui_auth_weekly_active_users',
    'Users with last_seen_at on or after Monday 00:00 of the current ISO calendar week (same tz as timezone.now()).',
)
_monthly_active_users = Gauge(
    'shellui_auth_monthly_active_users',
    'Users with last_seen_at in the current calendar month (timezone-aware now(), typically UTC).',
)

_successful_logins_total = Counter(
    'shellui_auth_successful_logins_total',
    'Successful OAuth login completions since this process started (browser callback or API login).',
    labelnames=('provider',),
)


def _count_user_activity_since(cutoff) -> int:
    return UserActivity.objects.filter(last_seen_at__gte=cutoff).count()


def _daily_active_users_count() -> int:
    now = timezone.now()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return _count_user_activity_since(day_start)


def _weekly_active_users_count() -> int:
    now = timezone.now()
    week_start = (now - timedelta(days=now.weekday())).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return _count_user_activity_since(week_start)


def _monthly_active_users_count() -> int:
    now = timezone.now()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return _count_user_activity_since(month_start)


def refresh_db_gauges() -> None:
    """Sync user-related gauges from the database before Prometheus serialization."""
    User = get_user_model()
    _users_total.set(User.objects.count())
    _users_active.set(User.objects.filter(is_active=True).count())
    _users_staff.set(User.objects.filter(is_staff=True).count())
    _social_accounts_total.set(SocialAccount.objects.count())
    _daily_active_users.set(_daily_active_users_count())
    _weekly_active_users.set(_weekly_active_users_count())
    _monthly_active_users.set(_monthly_active_users_count())


def record_successful_login(provider: str) -> None:
    p = (provider or 'unknown').strip().lower() or 'unknown'
    _successful_logins_total.labels(provider=p).inc()


def metrics_http_body() -> bytes:
    refresh_db_gauges()
    return generate_latest()


METRICS_CONTENT_TYPE = CONTENT_TYPE_LATEST
