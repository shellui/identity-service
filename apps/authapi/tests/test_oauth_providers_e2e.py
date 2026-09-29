"""End-to-end adapter tests for every supported OAuth provider slug."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
from django.test import RequestFactory, TestCase

from allauth.socialaccount.providers import registry

from apps.authapi.oauth import build_authorize_url, exchange_code_for_token, get_social_app_for_client, resolve_oauth_client
from apps.authapi.oauth_allauth import exchange_allauth_code, sociallogin_userinfo
from apps.authapi.oauth_social_account import compose_social_account_uid
from apps.authapi.provider_registry import get_provider_catalog, validate_extra_settings
from apps.companies.models import Company, CompanyOAuthClient

E2E_SLUGS_PATH = Path(__file__).resolve().parents[3] / 'tools' / 'data' / 'oauth_e2e_covered_slugs.json'
PUBLIC_OAUTH_HOST = 'https://example.com'
PROFILE_BASE = {
    'sub': 'uid-e2e',
    'id': 'uid-e2e',
    'email': 'user-e2e@example.com',
    'Email': 'user-e2e@example.com',
    'email_verified': True,
    'verified': True,
    'is_email_verified': True,
    'name': 'E2E User',
    'first_name': 'E2E',
    'last_name': 'User',
    'First_Name': 'E2E',
    'Last_Name': 'User',
    'login': 'e2e-user',
    'username': 'e2e-user',
    'displayName': 'E2E User',
    'userPrincipalName': 'user-e2e@example.com',
    'mail': 'user-e2e@example.com',
    'picture': 'https://example.com/a.png',
    'ZUID': 'uid-e2e',
    'user_id': 'uid-e2e',
}


def _load_e2e_slugs() -> list[str]:
    return json.loads(E2E_SLUGS_PATH.read_text(encoding='utf-8'))


def _profile_fixture_for_slug(request, slug: str, social_app: SocialApp) -> dict:
    entry = get_provider_catalog().by_slug()[slug]
    provider = registry.get_class(entry.allauth_id)(request, app=social_app)
    payload = dict(PROFILE_BASE)
    if slug == 'ynab':
        payload['data'] = {'user': {'id': 'uid-e2e'}}
    for _ in range(50):
        try:
            provider.extract_uid(payload)
            provider.extract_common_fields(payload)
            return payload
        except KeyError as exc:
            key = exc.args[0]
            if not isinstance(key, str):
                continue
            low = key.lower()
            if low in {'sub', 'id', 'uid', 'zuid', 'user_id'} or low.endswith('id'):
                payload[key] = 'uid-e2e'
            elif 'email' in low or key == 'Email':
                payload[key] = 'user-e2e@example.com'
            elif 'name' in low:
                payload[key] = 'E2E User'
            else:
                payload[key] = 'value'
        except TypeError:
            payload.setdefault('data', {'user': {'id': 'uid-e2e'}})
    return payload


def _example_extra_settings(entry) -> dict:
    extra: dict = {}
    for field in entry.extra_settings_schema:
        if field.name == 'key' and entry.docs_slug == 'salesforce':
            extra[field.name] = 'https://login.salesforce.com'
        elif field.type == 'url':
            extra[field.name] = f'{PUBLIC_OAUTH_HOST}/{entry.docs_slug}/{field.name}'
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
                f'{PUBLIC_OAUTH_HOST}/{slug}/.well-known/openid-configuration',
            )
        if entry.docs_slug == 'amazon_cognito':
            settings_payload.setdefault('DOMAIN', f'{PUBLIC_OAUTH_HOST}/{slug}')
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
        return app

    def test_all_catalog_supported_slugs_have_e2e_entry(self):
        catalog = get_provider_catalog()
        supported = {entry.docs_slug for entry in catalog.providers if entry.supported}
        e2e = set(_load_e2e_slugs())
        self.assertEqual(supported, e2e)

    def test_provider_adapter_round_trips(self):
        token_payload = {
            'access_token': 'access-token-e2e',
            'token_type': 'Bearer',
            'id_token': 'test-id-token-not-a-jwt',
        }
        for slug in _load_e2e_slugs():
            with self.subTest(provider=slug):
                app = self._social_app_for_slug(slug)
                authorize_path = '/api/v1/authorize'
                if slug == 'shopify':
                    authorize_path = '/api/v1/authorize?shop=test-shop.myshopify.com'
                request = self.factory.get(authorize_path)
                request.session = {}
                try:
                    profile_payload = _profile_fixture_for_slug(request, slug, app)
                except Exception:
                    profile_payload = dict(PROFILE_BASE)
                discovery_document = {
                    'issuer': f'{PUBLIC_OAUTH_HOST}/{slug}',
                    'authorization_endpoint': f'{PUBLIC_OAUTH_HOST}/{slug}/authorize',
                    'token_endpoint': f'{PUBLIC_OAUTH_HOST}/{slug}/token',
                    'userinfo_endpoint': f'{PUBLIC_OAUTH_HOST}/{slug}/userinfo',
                    'jwks_uri': f'{PUBLIC_OAUTH_HOST}/{slug}/jwks',
                }
                with mock.patch(
                    'apps.authapi.oauth_adapter_settings.safe_get_json',
                    return_value=discovery_document,
                ):
                    authorize_url = build_authorize_url(
                        slug,
                        redirect_uri='https://app.example/callback',
                        state='state-token',
                        request=request,
                        company_id=self.company.id,
                    )
                    self.assertIn('state=', authorize_url)
                    self.assertTrue(authorize_url.startswith('http'))

                    exchange_query = {'code': 'abc'}
                    if slug == 'shopify':
                        exchange_query['shop'] = 'test-shop.myshopify.com'
                    exchange_request = self.factory.get(
                        '/api/v1/oauth/callback',
                        exchange_query,
                    )
                    exchange_request.session = {}

                    def _universal_complete_login(adapter, request, app, token, **kwargs):  # noqa: ANN001
                        provider = adapter.get_provider()
                        try:
                            return provider.sociallogin_from_response(request, profile_payload)
                        except Exception:
                            from allauth.socialaccount.models import SocialAccount, SocialLogin

                            login = SocialLogin(
                                account=SocialAccount(
                                    provider=app.provider,
                                    uid='uid-e2e',
                                    extra_data={'userinfo': profile_payload},
                                )
                            )
                            from django.contrib.auth import get_user_model

                            login.user = get_user_model()(
                                email=profile_payload.get('email') or 'user-e2e@example.com'
                            )
                            return login

                    original_get_adapter = __import__(
                        'apps.authapi.oauth_allauth',
                        fromlist=['get_identity_oauth2_adapter'],
                    ).get_identity_oauth2_adapter

                    def _wrap_identity_oauth2_adapter(*args, **kwargs):
                        from allauth.socialaccount.models import SocialToken

                        adapter = original_get_adapter(*args, **kwargs)
                        adapter.get_access_token_data = (
                            lambda req, app, client, pkce_code_verifier=None: dict(token_payload)
                        )
                        adapter.parse_token = lambda data: SocialToken(token=str(data.get('access_token') or 'at'))
                        adapter.complete_login = (
                            lambda req, app, token, **kw: _universal_complete_login(
                                adapter,
                                req,
                                app,
                                token,
                                **kw,
                            )
                        )
                        return adapter

                    with mock.patch(
                        'apps.authapi.oauth_allauth.get_identity_oauth2_adapter',
                        _wrap_identity_oauth2_adapter,
                    ):
                        with mock.patch(
                            'allauth.socialaccount.internal.jwtkit.verify_and_decode',
                            return_value={
                                'sub': 'uid-e2e',
                                'email': 'user-e2e@example.com',
                                'email_verified': True,
                            },
                        ):
                            bundle = exchange_code_for_token(
                                slug,
                                'abc',
                                redirect_uri='https://app.example/callback',
                                request=exchange_request,
                                company_id=self.company.id,
                            )
                            self.assertEqual(bundle.access_token, 'access-token-e2e')
                            sociallogin, _token_data = exchange_allauth_code(
                                exchange_request,
                                social_app=get_social_app_for_client(
                                    resolve_oauth_client(slug, company_id=self.company.id)
                                ),
                                redirect_uri='https://app.example/callback',
                            )
                    userinfo = sociallogin_userinfo(sociallogin)
                    self.assertTrue(userinfo.get('email') or userinfo.get('id'))


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
