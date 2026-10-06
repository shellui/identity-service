"""Company-scoped ``GET /api/v1/metrics`` must only expose the caller's company.

Before 0.7.0 the company endpoint returned the whole default Prometheus registry: process and
Python runtime metrics, platform-wide user gauges, login counters for every company and the
``shellui_auth_company_*`` series of every company scraped earlier by the same process.
"""

from __future__ import annotations

import re

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.authapi import metrics as auth_metrics
from apps.authapi.views import _issue_personal_access_token, _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

_COMPANY_GAUGES = (
    'shellui_auth_company_users_total',
    'shellui_auth_company_users_active',
    'shellui_auth_company_users_staff',
    'shellui_auth_company_social_accounts_total',
    'shellui_auth_company_daily_active_users',
    'shellui_auth_company_weekly_active_users',
    'shellui_auth_company_monthly_active_users',
)


def _sample_names(body: str) -> set[str]:
    return {line.split('{')[0].split(' ')[0] for line in body.splitlines() if line and not line.startswith('#')}


class CompanyMetricsIsolationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.acme = Company.objects.create(name='Acme', slug='acme-metrics-iso')
        self.globex = Company.objects.create(name='Globex', slug='globex-metrics-iso')
        self.owner_a = User.objects.create_user(username='owner-a', email='a@acme.test', password='x')
        self.owner_b = User.objects.create_user(username='owner-b', email='b@globex.test', password='x')
        self.staff = User.objects.create_user(username='staff', email='s@x.test', password='x', is_staff=True)
        set_company_access(self.acme, self.owner_a, enabled=True)
        self.acme.owners.add(self.owner_a)
        set_company_access(self.globex, self.owner_b, enabled=True)
        self.globex.owners.add(self.owner_b)
        for i in range(3):
            user = User.objects.create_user(username=f'g{i}', email=f'g{i}@globex.test', password='x')
            set_company_access(self.globex, user, enabled=True)
        set_company_access(self.acme, self.staff, enabled=True)
        auth_metrics.record_successful_login('github', self.globex.id)
        auth_metrics.record_successful_login('google', self.acme.id)

    def _scrape(self, user, company, path='/api/v1/metrics'):
        token = _issue_shellui_tokens(user, company=company)['access_token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        return self.client.get(path)

    def _acme_owner_body(self) -> str:
        # Other tenants and staff scrape first, so the process-wide registry holds their series.
        self.assertEqual(self._scrape(self.staff, self.acme, '/api/v1/metrics/all').status_code, 200)
        self.assertEqual(self._scrape(self.owner_b, self.globex).status_code, 200)
        response = self._scrape(self.owner_a, self.acme)
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_owner_sees_no_other_company(self):
        body = self._acme_owner_body()
        self.assertNotIn(f'company_id="{self.globex.id}"', body)
        for company_id in re.findall(r'company_id="(\d+)"', body):
            self.assertEqual(company_id, str(self.acme.id))

    def test_owner_sees_no_platform_or_runtime_metrics(self):
        names = _sample_names(self._acme_owner_body())
        leaked = sorted(
            n
            for n in names
            if n.startswith(('process_', 'python_', 'shellui_auth_scheduled_job', 'shellui_auth_scheduler'))
            or n
            in {
                'shellui_auth_users_total',
                'shellui_auth_users_active',
                'shellui_auth_users_staff',
                'shellui_auth_social_accounts_total',
                'shellui_auth_daily_active_users',
                'shellui_auth_weekly_active_users',
                'shellui_auth_monthly_active_users',
            }
        )
        self.assertEqual(leaked, [])

    def test_owner_gets_own_company_series(self):
        body = self._acme_owner_body()
        cid = self.acme.id
        for name in _COMPANY_GAUGES:
            self.assertRegex(body, rf'(?m)^{name}{{company_id="{cid}"}} \d')
        self.assertIn(f'shellui_auth_company_users_total{{company_id="{cid}"}} 2.0', body)
        self.assertIn(f'shellui_auth_company_users_staff{{company_id="{cid}"}} 1.0', body)
        # The login counter is process-wide, so earlier tests may have bumped it.
        self.assertRegex(body, rf'(?m)^shellui_auth_successful_logins_total{{company_id="{cid}",provider="google"}} \d')
        for line in body.splitlines():
            if line.startswith('shellui_auth_successful_logins_total'):
                self.assertIn(f'company_id="{cid}"', line)

    def test_other_owner_gets_its_own_numbers(self):
        self._acme_owner_body()
        body = self._scrape(self.owner_b, self.globex).content.decode()
        gid = self.globex.id
        self.assertIn(f'shellui_auth_company_users_total{{company_id="{gid}"}} 4.0', body)
        self.assertNotIn(f'company_id="{self.acme.id}"', body)

    def test_staff_on_company_endpoint_is_company_scoped_too(self):
        self._scrape(self.owner_b, self.globex)
        body = self._scrape(self.staff, self.acme).content.decode()
        self.assertNotIn(f'company_id="{self.globex.id}"', body)
        self.assertNotIn('process_', body)

    def test_company_pat_is_company_scoped(self):
        self._scrape(self.owner_b, self.globex)
        _pat, raw = _issue_personal_access_token(self.owner_a, self.acme, read_only=True)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {raw}')
        response = self.client.get('/api/v1/metrics')
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertNotIn(f'company_id="{self.globex.id}"', body)
        self.assertIn(f'shellui_auth_company_users_total{{company_id="{self.acme.id}"}}', body)
        self.assertEqual(self.client.get('/api/v1/metrics/all').status_code, 403)

    def test_global_endpoint_still_has_everything_for_staff(self):
        self.assertEqual(self._scrape(self.owner_a, self.acme, '/api/v1/metrics/all').status_code, 403)
        body = self._scrape(self.staff, self.acme, '/api/v1/metrics/all').content.decode()
        self.assertIn('shellui_auth_users_total 6.0', body)
        self.assertIn(f'company_id="{self.globex.id}"', body)
        self.assertIn('shellui_auth_scheduler_enabled', body)

    def test_global_metrics_pat_reaches_global_endpoint(self):
        _pat, raw = _issue_personal_access_token(self.staff, self.acme, read_only=True, access_global_metrics=True)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {raw}')
        response = self.client.get('/api/v1/metrics/all')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'shellui_auth_users_total', response.content)
