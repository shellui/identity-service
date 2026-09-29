"""Strict per-provider OAuth adapter tests (real JWT verification, exact HTTP routes)."""

from __future__ import annotations

import json
from pathlib import Path

from django.contrib.sites.models import Site
from django.test import RequestFactory, TestCase

from apps.authapi.provider_registry import get_provider_catalog, validate_extra_settings
from apps.authapi.tests.oauth_real_provider_harness import authorize_get_path, prepare_social_app_for_audit
from apps.authapi.tests.oauth_strict_harness import run_strict_provider_round_trip
from apps.companies.models import Company, CompanyOAuthClient
from allauth.socialaccount.models import SocialApp

E2E_SLUGS_PATH = Path(__file__).resolve().parents[3] / 'tools' / 'data' / 'oauth_e2e_covered_slugs.json'


def _load_e2e_slugs() -> list[str]:
    return json.loads(E2E_SLUGS_PATH.read_text(encoding='utf-8'))


def _example_extra_settings(entry, *, company_slug: str) -> dict:
    extra: dict = {}
    for field in entry.extra_settings_schema:
        if field.name == 'key' and entry.docs_slug == 'salesforce':
            extra[field.name] = 'https://login.salesforce.com'
        elif field.type == 'url':
            if field.name == 'GITEA_URL':
                extra[field.name] = f'https://gitea.{company_slug}.example.com'
            elif field.name in {'REST_API', 'MEDIAWIKI_URL'}:
                extra[field.name] = f'https://wiki.{company_slug}.example.com'
            else:
                extra[field.name] = f'https://{entry.docs_slug}.example.com'
        elif field.secret:
            extra[field.name] = 'secret-value'
        elif field.name == 'tenant':
            extra[field.name] = 'common'
        else:
            extra[field.name] = f'test-{field.name}'
    normalized, errors = validate_extra_settings(entry, extra)
    return normalized if not errors else {'catalog_slug': entry.docs_slug}


class OAuthStrictProviderTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.company = Company.objects.create(name='Strict Co', slug='strict-co')
        self.site = Site.objects.get_current()

    def test_catalog_supported_matches_strict_e2e_list(self):
        supported = {e.docs_slug for e in get_provider_catalog().providers if e.supported}
        e2e = set(_load_e2e_slugs())
        self.assertEqual(supported, e2e)

    def test_strict_provider_round_trips(self):
        catalog = get_provider_catalog()
        for slug in _load_e2e_slugs():
            entry = catalog.by_slug()[slug]
            with self.subTest(provider=slug):
                settings_payload = _example_extra_settings(entry, company_slug=self.company.slug)
                if entry.allauth_id == 'openid_connect':
                    settings_payload['server_url'] = f'https://{slug}.example.com/.well-known/openid-configuration'
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
                )
                self.assertIsNone(err, err)

    def test_battlenet_china_uid_suffix(self):
        from allauth.socialaccount.providers import registry

        request = self.factory.get('/')
        app = SocialApp.objects.create(
            provider='battlenet',
            name='bn',
            client_id='bn-client',
            secret='secret',
        )
        provider = registry.get_class('battlenet')(request, app=app)
        profile = {'id': 7, 'battletag': 'Cn#7', 'region': 'cn'}
        self.assertEqual(provider.extract_uid(profile), '7-cn')
