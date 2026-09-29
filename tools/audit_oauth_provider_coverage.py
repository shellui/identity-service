#!/usr/bin/env python3
"""Print provider slugs whose real adapter harness passes (for oauth_e2e_covered_slugs.json)."""

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

from apps.authapi.oauth import build_authorize_url
from apps.authapi.oauth_allauth import exchange_allauth_code
from apps.authapi.provider_registry import get_provider_catalog, validate_extra_settings
from apps.authapi.tests.oauth_real_provider_harness import (
    PUBLIC_HOST,
    authorize_get_path,
    build_profile_for_provider,
    discovery_document_for_slug,
    oauth_provider_http_mock,
    prepare_social_app_for_audit,
)
from apps.companies.models import Company, CompanyOAuthClient


def _example_extra_settings(entry) -> dict:
    extra: dict = {}
    for field in entry.extra_settings_schema:
        if field.type == 'url':
            extra[field.name] = f'{PUBLIC_HOST}/{entry.docs_slug}/{field.name}'
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
    if entry is None:
        return 'missing catalog entry'
    settings_payload = _example_extra_settings(entry)
    if entry.allauth_id == 'openid_connect':
        settings_payload.setdefault(
            'server_url',
            f'{PUBLIC_HOST}/{slug}/.well-known/openid-configuration',
        )
    app = SocialApp.objects.create(
        provider=entry.allauth_id,
        provider_id=entry.social_app_provider_id(),
        name=f'audit-{slug}',
        client_id=f'client-{slug}',
        secret='secret',
        settings={**settings_payload, 'created_by_company_id': company.id},
    )
    app.sites.add(site)
    CompanyOAuthClient.objects.create(company=company, social_app=app, is_active=True)
    prepare_social_app_for_audit(slug, app)
    request = factory.get(authorize_get_path(slug))
    request.session = {}
    try:
        profile_payload = build_profile_for_provider(request, slug, app)
    except Exception as exc:
        return f'profile fixture: {exc}'
    discovery = discovery_document_for_slug(slug)
    try:
        with oauth_provider_http_mock(
            slug=slug,
            request=request,
            social_app=app,
            profile=profile_payload,
            discovery=discovery,
        ):
            authorize_url = build_authorize_url(
                slug,
                redirect_uri='https://app.example/callback',
                state='state-token',
                request=request,
                company_id=company.id,
                require_supported=False,
            )
            if not authorize_url.startswith('http'):
                return 'authorize url missing'
            exchange_query = {'code': 'abc'}
            if slug == 'shopify':
                exchange_query['shop'] = 'test-shop.myshopify.com'
            exchange_request = factory.get('/api/v1/oauth/callback', exchange_query)
            exchange_request.session = {}
            exchange_allauth_code(
                exchange_request,
                social_app=app,
                redirect_uri='https://app.example/callback',
            )
    except Exception as exc:
        return str(exc)
    finally:
        CompanyOAuthClient.objects.filter(social_app=app).delete()
        app.delete()
    return None


def main() -> int:
    factory = RequestFactory()
    company, _ = Company.objects.get_or_create(slug='audit-co', defaults={'name': 'Audit Co'})
    site = Site.objects.get_current()
    catalog = get_provider_catalog()
    candidates = [
        entry.docs_slug
        for entry in catalog.providers
        if entry.protocol in {'OAuth2', 'OpenID Connect'} and not entry.legacy
    ]
    passing: list[str] = []
    failing: dict[str, str] = {}
    for slug in sorted(candidates):
        err = _try_slug(slug, company=company, site=site, factory=factory)
        if err is None:
            passing.append(slug)
        else:
            failing[slug] = err
    out_path = ROOT / 'tools' / 'data' / 'oauth_e2e_covered_slugs.json'
    out_path.write_text(json.dumps(passing, indent=2) + '\n', encoding='utf-8')
    print(f'Passing: {len(passing)} -> {out_path}')
    for slug, reason in sorted(failing.items())[:30]:
        print(f'  FAIL {slug}: {reason[:120]}')
    if len(failing) > 30:
        print(f'  ... and {len(failing) - 30} more failures')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
