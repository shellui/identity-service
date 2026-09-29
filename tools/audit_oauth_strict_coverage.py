#!/usr/bin/env python3
"""Print provider slugs that pass strict OAuth adapter tests."""

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

from apps.authapi.provider_registry import get_provider_catalog, validate_extra_settings
from apps.authapi.tests.oauth_real_provider_harness import PUBLIC_HOST, authorize_get_path, prepare_social_app_for_audit
from apps.authapi.tests.oauth_strict_harness import run_strict_provider_round_trip
from apps.companies.models import Company, CompanyOAuthClient

OUT_PATH = ROOT / 'tools' / 'data' / 'oauth_e2e_covered_slugs.json'
HIDDEN_PROVIDER_SLUGS = frozenset({'edmodo'})


def _example_extra_settings(entry, *, company_slug: str = 'strict-audit-co') -> dict:
    extra: dict = {}
    for field in entry.extra_settings_schema:
        if field.name == 'key' and entry.docs_slug == 'salesforce':
            extra[field.name] = 'https://login.salesforce.com'
        elif field.type == 'url':
            if field.name == 'AUTH0_URL':
                extra[field.name] = 'https://auth0.example.com'
            elif field.name == 'OKTA_BASE_URL':
                extra[field.name] = 'https://okta.example.com'
            elif field.name == 'DOMAIN':
                extra[field.name] = 'https://cognito.example.com'
            elif field.name == 'GITEA_URL':
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


def _try_slug(slug: str, *, company: Company, site: Site, factory: RequestFactory) -> str | None:
    catalog = get_provider_catalog()
    entry = catalog.by_slug().get(slug)
    if entry is None or entry.legacy or entry.docs_slug in HIDDEN_PROVIDER_SLUGS:
        return 'legacy or missing'
    if entry.protocol not in {'OAuth2', 'OpenID Connect'}:
        return f'protocol {entry.protocol}'
    settings_payload = _example_extra_settings(entry, company_slug=company.slug)
    if entry.allauth_id == 'openid_connect':
        settings_payload['server_url'] = f'https://{slug}.example.com/.well-known/openid-configuration'
    if entry.docs_slug == 'salesforce':
        settings_payload.setdefault('key', 'https://login.salesforce.com')
    app = SocialApp.objects.create(
        provider=entry.allauth_id,
        provider_id=entry.social_app_provider_id(),
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
    err = run_strict_provider_round_trip(slug=slug, request=request, social_app=app, company_id=company.id)
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
    catalog = get_provider_catalog()
    passing: list[str] = []
    failures: dict[str, str] = {}
    for entry in catalog.providers:
        slug = entry.docs_slug
        if (
            entry.legacy
            or entry.hidden
            or entry.docs_slug in HIDDEN_PROVIDER_SLUGS
            or entry.protocol not in {'OAuth2', 'OpenID Connect'}
        ):
            continue
        err = _try_slug(slug, company=company, site=site, factory=factory)
        if err:
            failures[slug] = err
        else:
            passing.append(slug)
    passing.sort()
    OUT_PATH.write_text(json.dumps(passing, indent=2) + '\n', encoding='utf-8')
    print(f'passing={len(passing)} wrote {OUT_PATH}')
    for slug, err in sorted(failures.items())[:30]:
        print(f'  {slug}: {err}')
    if len(failures) > 30:
        print(f'  ... and {len(failures) - 30} more failures')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
