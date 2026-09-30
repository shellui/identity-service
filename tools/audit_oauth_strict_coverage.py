#!/usr/bin/env python3
"""Verify release supported providers pass strict OAuth adapter tests."""

from __future__ import annotations

import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
os.environ.setdefault('SECRET_KEY', 'audit-only-not-for-production')
os.environ.setdefault('DEBUG', 'true')

import django

django.setup()

from django.contrib.sites.models import Site
from django.test import RequestFactory

from allauth.socialaccount.models import SocialApp

from apps.authapi.provider_registry import get_provider_catalog
from apps.authapi.tests.oauth_supported_provider_fixtures import (
    RELEASE_SUPPORTED_OAUTH_SLUGS,
    extra_settings_for_supported,
)
from apps.authapi.tests.oauth_strict_harness import (
    STRICT_LOGIN_CALLBACK_SLUGS,
    run_strict_login_callback_round_trip,
    run_strict_provider_round_trip,
)
from apps.authapi.tests.oauth_test_utilities import authorize_get_path, prepare_social_app_for_audit
from apps.companies.models import Company, CompanyOAuthClient

OUT_PATH = ROOT / 'tools' / 'data' / 'oauth_e2e_covered_slugs.json'


def _try_slug(slug: str, *, company: Company, site: Site, factory: RequestFactory) -> str | None:
    catalog = get_provider_catalog()
    entry = catalog.by_slug().get(slug)
    if entry is None:
        return 'missing catalog entry'
    settings_payload = extra_settings_for_supported(slug, company_slug=company.slug)
    provider_id = entry.social_app_provider_id()
    if entry.allauth_id == 'openid_connect' and not provider_id:
        provider_id = 'corp-fixture'
    app = SocialApp.objects.create(
        provider=entry.allauth_id,
        provider_id=provider_id,
        name=f'strict-{slug}',
        client_id=f'client-{slug}',
        secret='secret',
        key=str(settings_payload.get('key') or ''),
        settings={**settings_payload, 'created_by_company_id': company.id},
    )
    app.sites.add(site)
    CompanyOAuthClient.objects.create(company=company, social_app=app, is_active=True)
    prepare_social_app_for_audit(slug, app)
    request = factory.get(authorize_get_path(slug))
    request.session = {}
    if slug in STRICT_LOGIN_CALLBACK_SLUGS:
        err = run_strict_login_callback_round_trip(
            slug=slug,
            request=request,
            social_app=app,
            company_id=company.id,
            company_slug=company.slug,
        )
    else:
        err = run_strict_provider_round_trip(
            slug=slug,
            request=request,
            social_app=app,
            company_id=company.id,
            company_slug=company.slug,
        )
    CompanyOAuthClient.objects.filter(social_app=app).delete()
    app.delete()
    return err


def main() -> int:
    company, _ = Company.objects.get_or_create(
        slug='strict-audit-co',
        defaults={'name': 'Strict Audit Co'},
    )
    site = Site.objects.get_current()
    factory = RequestFactory()
    passing: list[str] = []
    failures: dict[str, str] = {}
    for slug in sorted(RELEASE_SUPPORTED_OAUTH_SLUGS):
        err = _try_slug(slug, company=company, site=site, factory=factory)
        if err:
            failures[slug] = err
        else:
            passing.append(slug)
    if failures:
        for slug, err in sorted(failures.items()):
            print(f'FAIL {slug}: {err}', file=sys.stderr)
        return 1
    OUT_PATH.write_text(json.dumps(passing, indent=2) + '\n', encoding='utf-8')
    print(f'passing={len(passing)} wrote {OUT_PATH}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
