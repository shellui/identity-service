"""Real adapter tests per supported catalog provider (no complete_login stubs)."""

from __future__ import annotations

import json
from pathlib import Path
from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
from django.test import RequestFactory, TestCase

from apps.authapi.oauth import build_authorize_url, exchange_code_for_token, get_social_app_for_client, resolve_oauth_client
from apps.authapi.oauth_allauth import exchange_allauth_code, sociallogin_userinfo
from apps.authapi.oauth_social_account import compose_social_account_uid
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
from tools.audit_oauth_provider_coverage import _try_slug

E2E_SLUGS_PATH = Path(__file__).resolve().parents[3] / 'tools' / 'data' / 'oauth_e2e_covered_slugs.json'
PROFILE_BASE = {}


def _load_e2e_slugs() -> list[str]:
    return json.loads(E2E_SLUGS_PATH.read_text(encoding='utf-8'))


def _example_extra_settings(entry) -> dict:
    extra: dict = {}
    for field in entry.extra_settings_schema:
        if field.name == 'key' and entry.docs_slug == 'salesforce':
            extra[field.name] = 'https://login.salesforce.com'
        elif field.type == 'url':
            extra[field.name] = f'{PUBLIC_HOST}/{entry.docs_slug}/{field.name}'
        elif field.secret:
            extra[field.name] = 'secret-value'
        elif field.name == 'tenant':
            extra[field.name] = 'common'
        else:
            extra[field.name] = f'test-{field.name}'
    normalized, errors = validate_extra_settings(entry, extra)
    if errors:
        return {'catalog_slug': entry.docs_slug}
    return normalized


class OAuthProviderE2ETests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.company = Company.objects.create(name='E2E Co', slug='e2e-co')
        self.site = Site.objects.get_current()

    def _social_app_for_slug(self, slug: str) -> SocialApp:
        entry = get_provider_catalog().by_slug()[slug]
        settings_payload = _example_extra_settings(entry)
        if entry.allauth_id == 'openid_connect':
            settings_payload.setdefault(
                'server_url',
                f'{PUBLIC_HOST}/{slug}/.well-known/openid-configuration',
            )
        if entry.docs_slug == 'amazon_cognito':
            settings_payload.setdefault('DOMAIN', f'{PUBLIC_HOST}/{slug}')
        app = SocialApp.objects.create(
            provider=entry.allauth_id,
            provider_id=entry.social_app_provider_id(),
            name=f'e2e-{slug}',
            client_id=f'client-{slug}',
            secret='secret',
            key=str(settings_payload.get('key') or ''),
            settings=settings_payload,
        )
        app.sites.add(self.site)
        CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        prepare_social_app_for_audit(slug, app)
        return app

    def test_all_catalog_supported_slugs_have_e2e_entry(self):
        catalog = get_provider_catalog()
        supported = {entry.docs_slug for entry in catalog.providers if entry.supported}
        e2e = set(_load_e2e_slugs())
        self.assertEqual(supported, e2e)

    def test_provider_adapter_round_trips(self):
        catalog = get_provider_catalog()
        for slug in _load_e2e_slugs():
            entry = catalog.by_slug()[slug]
            with self.subTest(provider=slug):
                app = self._social_app_for_slug(slug)
                request = self.factory.get(authorize_get_path(slug))
                request.session = {}
                profile_payload = build_profile_for_provider(request, slug, app)
                discovery = discovery_document_for_slug(slug)
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
                        company_id=self.company.id,
                    )
                    self.assertIn('state=', authorize_url)
                    parsed_host = authorize_url.split('/')[2]
                    self.assertTrue(parsed_host)

                    exchange_query = {'code': 'abc'}
                    if slug == 'shopify':
                        exchange_query['shop'] = 'test-shop.myshopify.com'
                    exchange_request = self.factory.get(
                        '/api/v1/oauth/callback',
                        exchange_query,
                    )
                    exchange_request.session = {}
                    bundle = exchange_code_for_token(
                        slug,
                        'abc',
                        redirect_uri='https://app.example/callback',
                        request=exchange_request,
                        company_id=self.company.id,
                    )
                    self.assertTrue(bundle.access_token)
                    sociallogin, _token_data = exchange_allauth_code(
                        exchange_request,
                        social_app=get_social_app_for_client(
                            resolve_oauth_client(slug, company_id=self.company.id)
                        ),
                        redirect_uri='https://app.example/callback',
                    )
                    userinfo = sociallogin_userinfo(sociallogin)
                    self.assertTrue(sociallogin.account.uid)
                    self.assertTrue(userinfo.get('email') or userinfo.get('id'))


class OAuthProviderAuditSlugTests(TestCase):
    def test_slack_audit_harness_passes(self):
        company = Company.objects.create(name='Slack Audit', slug='slack-audit')
        err = _try_slug(
            'slack',
            company=company,
            site=Site.objects.get_current(),
            factory=RequestFactory(),
        )
        self.assertIsNone(err, err)


class OpenIdSocialAccountKeyTests(TestCase):
    def test_two_issuers_same_sub_do_not_collide(self):
        entry = get_provider_catalog().by_slug()['keycloak']
        app_a = SocialApp(
            provider='openid_connect',
            provider_id='tenant-a',
            settings={'catalog_slug': 'keycloak', 'server_url': 'https://issuer-a.example.com'},
        )
        app_b = SocialApp(
            provider='openid_connect',
            provider_id='tenant-b',
            settings={'catalog_slug': 'keycloak', 'server_url': 'https://issuer-b.example.com'},
        )
        uid_a = compose_social_account_uid(
            entry=entry,
            social_app=app_a,
            raw_uid='same-sub',
            id_token_claims={'iss': 'https://issuer-a.example.com'},
        )
        uid_b = compose_social_account_uid(
            entry=entry,
            social_app=app_b,
            raw_uid='same-sub',
            id_token_claims={'iss': 'https://issuer-b.example.com'},
        )
        self.assertNotEqual(uid_a, uid_b)
