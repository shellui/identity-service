"""Prometheus metrics for shellui-auth.

Two expositions:

- ``GET /api/v1/metrics/all`` (staff or a ``pat_agm`` token): the process-wide default registry
  (runtime, platform user gauges, logins for every company) plus scheduled job metrics.
- ``GET /api/v1/metrics`` (company owner or staff, company from the token): a per-request
  registry holding only that company's series. Nothing process-wide or from another company.
"""

from __future__ import annotations

from datetime import timedelta

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.utils import timezone
from apps.companies.models import Company, CompanyMembership
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

from .models import UserActivity

_users_total = Gauge('shellui_auth_users_total', 'Number of Django user rows.')
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
    labelnames=('provider', 'company_id'),
)

# Company-scoped series: built per request from the database, never stored in the default
# registry (labelled gauges there kept every scraped company and leaked across tenants).
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


def company_gauge_values(company: Company) -> dict[str, int]:
    """Current value of each ``shellui_auth_company_*`` gauge for one company."""
    users = get_user_model().objects.filter(companies=company).distinct()
    now = timezone.now()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
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


class CompanyMetricsCollector:
    """One company's series only: DB gauges plus this process's login counter for that company."""

    def __init__(self, company: Company):
        self.company = company

    def collect(self):
        company_id = str(self.company.id)
        values = company_gauge_values(self.company)
        for name, documentation in _COMPANY_GAUGES:
            family = GaugeMetricFamily(name, documentation, labels=('company_id',))
            family.add_metric((company_id,), values[name])
            yield family

        logins = CounterMetricFamily(
            'shellui_auth_successful_logins',
            _successful_logins_total._documentation,
            labels=('company_id', 'provider'),
        )
        for metric in _successful_logins_total.collect():
            for sample in metric.samples:
                if sample.name.endswith('_total') and sample.labels.get('company_id') == company_id:
                    logins.add_metric((company_id, sample.labels['provider']), sample.value)
        yield logins


def company_metrics_body(company: Company) -> bytes:
    registry = CollectorRegistry(auto_describe=False)
    registry.register(CompanyMetricsCollector(company))
    return generate_latest(registry)


def record_successful_login(provider: str, company_id: int) -> None:
    p = (provider or 'unknown').strip().lower() or 'unknown'
    _successful_logins_total.labels(provider=p, company_id=str(company_id)).inc()


def metrics_http_body(company_id: int | None = None) -> bytes:
    """Global exposition when ``company_id`` is None, else that company's series only."""
    if company_id is None:
        refresh_db_gauges()
        # Platform metrics (scheduled jobs) are global only, never in a company scrape.
        from apps.actions.scheduled_job_metrics import scheduled_jobs_metrics_body

        return generate_latest() + scheduled_jobs_metrics_body()
    try:
        company = Company.objects.get(pk=company_id)
    except Company.DoesNotExist:
        return b''
    return company_metrics_body(company)


METRICS_CONTENT_TYPE = CONTENT_TYPE_LATEST
