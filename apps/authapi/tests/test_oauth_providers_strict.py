"""Strict OAuth adapter tests for the eight supported release providers."""

from __future__ import annotations

import json
from pathlib import Path

from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
from django.test import RequestFactory, TestCase

from apps.authapi.provider_registry import get_provider_catalog
from apps.authapi.tests.oauth_supported_provider_fixtures import (
    RELEASE_SUPPORTED_OAUTH_SLUGS,
    extra_settings_for_supported,
)
from apps.authapi.tests.oauth_strict_harness import run_strict_provider_round_trip
from apps.authapi.tests.oauth_test_utilities import authorize_get_path, prepare_social_app_for_audit
from apps.companies.models import Company, CompanyOAuthClient

E2E_SLUGS_PATH = Path(__file__).resolve().parents[3] / 'tools' / 'data' / 'oauth_e2e_covered_slugs.json'


def _load_e2e_slugs() -> list[str]:
    return json.loads(E2E_SLUGS_PATH.read_text(encoding='utf-8'))


class OAuthStrictProviderTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.company = Company.objects.create(name='Strict Co', slug='strict-co')
        self.site = Site.objects.get_current()

    def test_release_supported_slugs_are_exactly_eight(self):
        self.assertEqual(RELEASE_SUPPORTED_OAUTH_SLUGS, frozenset(_load_e2e_slugs()))

    def test_catalog_supported_matches_release_list(self):
        supported = {e.docs_slug for e in get_provider_catalog().providers if e.supported}
        self.assertEqual(supported, RELEASE_SUPPORTED_OAUTH_SLUGS)

    def test_strict_provider_round_trips(self):
        catalog = get_provider_catalog()
        for slug in _load_e2e_slugs():
            entry = catalog.by_slug()[slug]
            with self.subTest(provider=slug):
                settings_payload = extra_settings_for_supported(slug, company_slug=self.company.slug)
                app = SocialApp.objects.create(
                    provider=entry.allauth_id,
                    provider_id=entry.social_app_provider_id(),
                    name=f'strict-{slug}',
                    client_id=f'client-{slug}',
                    secret='secret',
                    key=str(settings_payload.get('key') or ''),
                    settings={**settings_payload, 'created_by_company_id': self.company.id},
                )
                app.sites.add(self.site)
                CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
                prepare_social_app_for_audit(slug, app)
                request = self.factory.get(authorize_get_path(slug))
                request.session = {}
                err = run_strict_provider_round_trip(
                    slug=slug,
                    request=request,
                    social_app=app,
                    company_id=self.company.id,
                    company_slug=self.company.slug,
                )
                self.assertIsNone(err, err)
