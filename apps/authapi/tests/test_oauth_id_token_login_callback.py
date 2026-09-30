"""OAuth callback id_token verification for OIDC providers (Shellui login path)."""

from __future__ import annotations

import time

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.oauth_state import OAUTH_STATE_NONCE_COOKIE, build_oauth_state, parse_oauth_state
from apps.authapi.tests.oauth_oidc_strict_fixtures import company_generic_oidc, company_keycloak_oidc
from apps.authapi.tests.oauth_strict_harness import (
    _build_linkedin_strict_spec,
    _build_oidc_strict_spec,
    strict_provider_http,
)
from apps.authapi.tests.oauth_supported_provider_fixtures import supported_provider_fixture
from apps.authapi.tests.oauth_test_crypto import generate_oauth_test_signing_key
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
    AUTH_RATE_LIMIT_ENABLED=False,
    OAUTH_TOKEN_DELIVERY='code',
    OAUTH_SKIP_CONFIRM_PROVIDERS=['linkedin', 'keycloak', 'openid_connect'],
)
class OidcIdTokenLoginCallbackTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='OIDC Callback Co', slug='oidc-callback-co')
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )
        self.victim = User.objects.create_user(
            username='victim-oidc',
            email='victim@example.com',
            password='unused',
        )

    def _callback_for_spec(self, *, slug: str, spec, oauth_client: CompanyOAuthClient):
        redirect_to = 'https://shell.example.com/login/callback'
        state, _nonce = build_oauth_state(
            provider=slug,
            redirect_to=redirect_to,
            company_id=self.company.id,
            company_oauth_client_id=oauth_client.id,
        )
        payload, err = parse_oauth_state(state)
        self.assertIsNone(err)
        assert payload is not None
        with strict_provider_http(spec):
            self.client.cookies[OAUTH_STATE_NONCE_COOKIE] = payload['nonce']
            return self.client.get('/api/v1/oauth/callback', {'code': 'oidc-code', 'state': state})

    def test_linkedin_wrong_signing_key_rejects_callback(self):
        from apps.authapi.tests.oauth_strict_harness import _token_json_handler

        fixture = supported_provider_fixture('linkedin')
        trusted = generate_oauth_test_signing_key(kid='linkedin-trusted')
        wrong = generate_oauth_test_signing_key(kid='linkedin-wrong')
        app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id='linkedin',
            name='linkedin-cb',
            client_id='linkedin-client',
            secret='secret',
            settings={'catalog_slug': 'linkedin', 'server_url': 'https://www.linkedin.com/oauth'},
        )
        oauth_client = CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        profile = dict(fixture.profile_document)
        spec = _build_linkedin_strict_spec(
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            signing=trusted,
        )
        now = int(time.time())
        bad_token = wrong.sign_rs256(
            {
                'iss': 'https://www.linkedin.com/oauth',
                'aud': app.client_id,
                'sub': fixture.expected_uid,
                'email': profile.get('email'),
                'email_verified': True,
                'exp': now + 3600,
                'iat': now,
            }
        )
        spec.routes[('www.linkedin.com', 'POST', '/oauth/v2/accessToken')] = _token_json_handler(
            {'access_token': 'at-linkedin', 'token_type': 'Bearer', 'id_token': bad_token}
        )
        before = User.objects.count()
        response = self._callback_for_spec(slug='linkedin', spec=spec, oauth_client=oauth_client)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(User.objects.count(), before)
        self.assertEqual(response.json().get('error_code'), 'oauth_id_token_invalid')

    def test_keycloak_malicious_email_returns_oauth_email_conflict(self):
        fixture = supported_provider_fixture('keycloak')
        signing = generate_oauth_test_signing_key(kid='kc-cb-kid')
        app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id='keycloak',
            name='kc-cb',
            client_id='kc-client',
            secret='secret',
            settings={
                'catalog_slug': 'keycloak',
                'server_url': company_keycloak_oidc(self.company.slug).server_url,
            },
        )
        oauth_client = CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        profile = dict(fixture.profile_document)
        profile['email'] = 'victim@example.com'
        spec = _build_oidc_strict_spec(
            slug='keycloak',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            signing=signing,
        )
        response = self._callback_for_spec(slug='keycloak', spec=spec, oauth_client=oauth_client)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json().get('error_code'), 'oauth_email_conflict')

    def test_openid_connect_wrong_signing_key_rejects_callback(self):
        fixture = supported_provider_fixture('openid_connect')
        signing = generate_oauth_test_signing_key(kid='oidc-trusted')
        wrong = generate_oauth_test_signing_key(kid='oidc-wrong')
        app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id='corp-fixture',
            name='oidc-cb',
            client_id='oidc-client',
            secret='secret',
            settings={
                'catalog_slug': 'openid_connect',
                'server_url': company_generic_oidc(self.company.slug).server_url,
            },
        )
        oauth_client = CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        profile = dict(fixture.profile_document)
        spec = _build_oidc_strict_spec(
            slug='openid_connect',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            signing=wrong,
        )
        host = company_generic_oidc(self.company.slug).hostname
        from apps.authapi.tests.oauth_test_crypto import json_response_handler

        spec.routes[(host, 'GET', '/jwks')] = json_response_handler(signing.jwks_document())
        before = User.objects.count()
        response = self._callback_for_spec(slug='openid_connect', spec=spec, oauth_client=oauth_client)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(User.objects.count(), before)
        self.assertEqual(response.json().get('error_code'), 'oauth_id_token_invalid')

    def _linkedin_app(self) -> tuple[SocialApp, CompanyOAuthClient]:
        app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id='linkedin',
            name='linkedin-discovery',
            client_id='linkedin-client',
            secret='secret',
            settings={'catalog_slug': 'linkedin', 'server_url': 'https://www.linkedin.com/oauth'},
        )
        return app, CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)

    def _generic_oidc_app(self) -> tuple[SocialApp, CompanyOAuthClient]:
        app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id='corp-fixture',
            name='oidc-discovery',
            client_id='oidc-client',
            secret='secret',
            settings={
                'catalog_slug': 'openid_connect',
                'server_url': company_generic_oidc(self.company.slug).server_url,
            },
        )
        return app, CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)

    def test_linkedin_discovery_with_off_host_endpoints_rejects_callback(self):
        from apps.authapi.tests.oauth_strict_harness import _linkedin_discovery_document
        from apps.authapi.tests.oauth_test_crypto import json_response_handler

        fixture = supported_provider_fixture('linkedin')
        app, oauth_client = self._linkedin_app()
        for key, off_host_url in (
            ('authorization_endpoint', 'https://example.com/oauth/v2/authorization'),
            ('token_endpoint', 'https://example.com/oauth/v2/accessToken'),
            ('userinfo_endpoint', 'https://www.linkedin.com/v2/userinfo'),
            ('jwks_uri', 'https://api.linkedin.com/oauth/openid/jwks'),
        ):
            with self.subTest(endpoint=key):
                spec = _build_linkedin_strict_spec(
                    social_app=app,
                    fixture_expected_uid=fixture.expected_uid,
                    profile=dict(fixture.profile_document),
                )
                document = {**_linkedin_discovery_document(), key: off_host_url}
                spec.routes[('www.linkedin.com', 'GET', '/oauth/.well-known/openid-configuration')] = (
                    json_response_handler(document)
                )
                before = User.objects.count()
                response = self._callback_for_spec(slug='linkedin', spec=spec, oauth_client=oauth_client)
                self.assertEqual(response.status_code, 502)
                self.assertEqual(response.json().get('error_code'), 'oauth_provider_host_not_allowed')
                self.assertEqual(User.objects.count(), before)

    def test_linkedin_discovery_with_other_issuer_rejects_callback(self):
        from apps.authapi.tests.oauth_strict_harness import _linkedin_discovery_document
        from apps.authapi.tests.oauth_test_crypto import json_response_handler

        fixture = supported_provider_fixture('linkedin')
        app, oauth_client = self._linkedin_app()
        spec = _build_linkedin_strict_spec(
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=dict(fixture.profile_document),
        )
        document = {**_linkedin_discovery_document(), 'issuer': 'https://www.linkedin.com'}
        spec.routes[('www.linkedin.com', 'GET', '/oauth/.well-known/openid-configuration')] = (
            json_response_handler(document)
        )
        response = self._callback_for_spec(slug='linkedin', spec=spec, oauth_client=oauth_client)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json().get('error_code'), 'oauth_discovery_issuer_mismatch')

    def test_openid_connect_discovery_issuer_mismatch_rejects_callback(self):
        from apps.authapi.tests.oauth_strict_harness import _oidc_discovery_document
        from apps.authapi.tests.oauth_test_crypto import json_response_handler

        fixture = supported_provider_fixture('openid_connect')
        app, oauth_client = self._generic_oidc_app()
        oidc = company_generic_oidc(self.company.slug)
        spec = _build_oidc_strict_spec(
            slug='openid_connect',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=dict(fixture.profile_document),
        )
        document = {
            **_oidc_discovery_document(oidc),
            'issuer': company_keycloak_oidc('victim-co').issuer,
        }
        spec.routes[(oidc.hostname, 'GET', '/.well-known/openid-configuration')] = json_response_handler(document)
        before = User.objects.count()
        response = self._callback_for_spec(slug='openid_connect', spec=spec, oauth_client=oauth_client)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json().get('error_code'), 'oauth_discovery_issuer_mismatch')
        self.assertEqual(User.objects.count(), before)

    def test_openid_connect_discovery_issuer_mismatch_rejects_authorize(self):
        from apps.authapi.tests.oauth_strict_harness import _oidc_discovery_document
        from apps.authapi.tests.oauth_test_crypto import json_response_handler

        fixture = supported_provider_fixture('openid_connect')
        app, _oauth_client = self._generic_oidc_app()
        oidc = company_generic_oidc(self.company.slug)
        spec = _build_oidc_strict_spec(
            slug='openid_connect',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=dict(fixture.profile_document),
        )
        document = {**_oidc_discovery_document(oidc), 'issuer': 'https://example.com'}
        spec.routes[(oidc.hostname, 'GET', '/.well-known/openid-configuration')] = json_response_handler(document)
        with strict_provider_http(spec):
            response = self.client.get(
                '/api/v1/authorize',
                {
                    'provider': 'openid_connect',
                    'company_id': self.company.id,
                    'redirect_to': 'https://shell.example.com/login/callback',
                },
            )
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json().get('error_code'), 'oauth_discovery_issuer_mismatch')

    def test_keycloak_wrong_signing_key_rejects_callback(self):
        fixture = supported_provider_fixture('keycloak')
        signing = generate_oauth_test_signing_key(kid='kc-trusted')
        wrong = generate_oauth_test_signing_key(kid='kc-wrong')
        app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id='keycloak',
            name='kc-wrong-key',
            client_id='kc-client',
            secret='secret',
            settings={
                'catalog_slug': 'keycloak',
                'server_url': company_keycloak_oidc(self.company.slug).server_url,
            },
        )
        oauth_client = CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        profile = dict(fixture.profile_document)
        spec = _build_oidc_strict_spec(
            slug='keycloak',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            signing=wrong,
        )
        oidc = company_keycloak_oidc(self.company.slug)
        host = oidc.hostname
        from urllib.parse import urlparse

        from apps.authapi.tests.oauth_test_crypto import json_response_handler

        jwks_path = urlparse(f'{oidc.issuer}/jwks').path or '/jwks'
        spec.routes[(host, 'GET', jwks_path)] = json_response_handler(signing.jwks_document())
        before = User.objects.count()
        response = self._callback_for_spec(slug='keycloak', spec=spec, oauth_client=oauth_client)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(User.objects.count(), before)
        self.assertEqual(response.json().get('error_code'), 'oauth_id_token_invalid')
