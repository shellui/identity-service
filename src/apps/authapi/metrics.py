"""Prometheus-style metrics for shellui-auth; exposition is staff JWT–protected (see ShellUIAdminMetricsView)."""

from __future__ import annotations

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

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

_successful_logins_total = Counter(
    'shellui_auth_successful_logins_total',
    'Successful OAuth login completions since this process started (browser callback or API login).',
    labelnames=('provider',),
)


def refresh_db_gauges() -> None:
    """Sync user-related gauges from the database before Prometheus serialization."""
    User = get_user_model()
    _users_total.set(User.objects.count())
    _users_active.set(User.objects.filter(is_active=True).count())
    _users_staff.set(User.objects.filter(is_staff=True).count())
    _social_accounts_total.set(SocialAccount.objects.count())


def record_successful_login(provider: str) -> None:
    p = (provider or 'unknown').strip().lower() or 'unknown'
    _successful_logins_total.labels(provider=p).inc()


def metrics_http_body() -> bytes:
    refresh_db_gauges()
    return generate_latest()


METRICS_CONTENT_TYPE = CONTENT_TYPE_LATEST
