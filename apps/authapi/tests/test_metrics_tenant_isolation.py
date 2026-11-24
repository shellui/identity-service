"""Prometheus scrape endpoints are gone. Company gauges stay per company_id."""

from __future__ import annotations

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.authapi import metrics as auth_metrics
from apps.authapi.views import _issue_personal_access_token, _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()


class MetricsEndpointTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.acme = Company.objects.create(name='Acme', slug='acme-metrics-iso')
        self.globex = Company.objects.create(name='Globex', slug='globex-metrics-iso')
        self.owner_a = User.objects.create_user(username='owner-a', email='a@acme.test', password='x')
        self.staff = User.objects.create_user(username='staff', email='s@x.test', password='x', is_staff=True)
        set_company_access(self.acme, self.owner_a, enabled=True)
        self.acme.owners.add(self.owner_a)
        for i in range(3):
            user = User.objects.create_user(username=f'g{i}', email=f'g{i}@globex.test', password='x')
            set_company_access(self.globex, user, enabled=True)
        set_company_access(self.acme, self.staff, enabled=True)

    def test_metrics_endpoints_are_gone(self):
        token = _issue_shellui_tokens(self.staff, company=self.acme)['access_token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        self.assertEqual(self.client.get('/api/v1/metrics').status_code, 404)
        self.assertEqual(self.client.get('/api/v1/metrics/all').status_code, 404)

    def test_company_gauges_keep_company_id(self):
        acme = auth_metrics.company_gauge_values(self.acme)
        globex = auth_metrics.company_gauge_values(self.globex)
        self.assertEqual(acme['shellui_auth_company_users_total'], 2)
        self.assertEqual(acme['shellui_auth_company_users_staff'], 1)
        self.assertEqual(globex['shellui_auth_company_users_total'], 3)
        self.assertNotEqual(acme['shellui_auth_company_users_total'], globex['shellui_auth_company_users_total'])

    def test_new_pat_omits_global_metrics_claim(self):
        _row, raw = _issue_personal_access_token(self.owner_a, self.acme, read_only=True, name='ro')
        claims = jwt.decode(raw, options={'verify_signature': False})
        self.assertNotIn('pat_agm', claims)
        self.assertTrue(claims['pat_ro'])
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {raw}')
        self.assertEqual(self.client.get('/api/v1/metrics').status_code, 404)
        self.assertEqual(self.client.get('/api/v1/user').status_code, 200)

    def test_api_rejects_global_metrics_flag(self):
        token = _issue_shellui_tokens(self.staff, company=self.acme)['access_token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        response = self.client.post(
            '/api/v1/personal-access-tokens',
            {'read_only': True, 'access_global_metrics': True, 'name': 'scrape'},
            format='json',
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('access_global_metrics', response.data)
