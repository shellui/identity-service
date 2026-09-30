"""Cross-company uid scoping, GitLab email policy, and single id_token verification."""

from __future__ import annotations

import importlib
import time
import uuid
from urllib.parse import urlparse

from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import RequestFactory, TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.oauth_state import OAUTH_STATE_NONCE_COOKIE, build_oauth_state, parse_oauth_state
from apps.authapi.tests.oauth_oidc_strict_fixtures import (
    company_auth0_base,
    company_keycloak_oidc,
    company_okta_base,
)
from apps.authapi.tests.oauth_strict_harness import (
    StrictProviderSpec,
    _build_oidc_strict_spec,
    _json_handler,
    _token_json_handler,
    build_strict_spec,
    strict_provider_http,
)
from apps.authapi.tests.oauth_supported_provider_fixtures import (
    company_gitlab_url,
    supported_provider_fixture,
)
from apps.authapi.tests.oauth_test_crypto import generate_oauth_test_signing_key, json_response_handler
from apps.companies.models import Company, CompanyMembership, CompanyOAuthClient, CompanyOAuthRedirect

User = get_user_model()
_gitlab_migration = importlib.import_module('apps.authapi.migrations.0015_scope_self_hosted_gitlab_uids')


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
    AUTH_RATE_LIMIT_ENABLED=False,
    OAUTH_TOKEN_DELIVERY='code',
    OAUTH_SKIP_CONFIRM_PROVIDERS=['okta', 'auth0', 'gitlab', 'keycloak', 'slack', 'openid_connect'],
)
class CompanyIdpIsolationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Company A', slug='company-a')
        self.other = Company.objects.create(name='Company B', slug='company-b')
        for company in (self.company, self.other):
            CompanyOAuthRedirect.objects.create(
                company=company,
                base_url='https://shell.example.com',
                is_active=True,
            )
        self.victim = User.objects.create_user(username='victim-a', email='victim@example.com', password='x')

    def _callback(self, *, slug, spec, oauth_client, company):
        redirect_to = 'https://shell.example.com/login/callback'
        state, _nonce = build_oauth_state(
            provider=slug,
            redirect_to=redirect_to,
            company_id=company.id,
            company_oauth_client_id=oauth_client.id,
        )
        payload, err = parse_oauth_state(state)
        self.assertIsNone(err)
        assert payload is not None
        with strict_provider_http(spec):
            self.client.cookies[OAUTH_STATE_NONCE_COOKIE] = payload['nonce']
            return self.client.get('/api/v1/oauth/callback', {'code': 'idp-code', 'state': state})

    def _app(self, *, company, provider, provider_id, name, client_id, settings):
        app = SocialApp.objects.create(
            provider=provider,
            provider_id=provider_id,
            name=name,
            client_id=client_id,
            secret='secret',
            settings=settings,
        )
        oauth_client = CompanyOAuthClient.objects.create(company=company, social_app=app, is_active=True)
        return app, oauth_client

    def _signed(self, signing, *, iss, aud, sub, email, jti=None):
        now = int(time.time())
        payload = {
            'iss': iss,
            'aud': aud,
            'sub': sub,
            'email': email,
            'email_verified': True,
            'exp': now + 3600,
            'iat': now,
            'jti': jti or str(uuid.uuid4()),
        }
        return signing.sign_rs256(payload)

    def _okta_spec(self, *, base, client_id, sub, email, signing, token=None):
        host = urlparse(base).hostname
        id_token = token or self._signed(signing, iss=base, aud=client_id, sub=sub, email=email)
        profile = {
            'sub': sub,
            'email': email,
            'email_verified': True,
            'given_name': 'Okta',
            'family_name': 'User',
        }
        routes = {
            (host, 'POST', '/oauth2/v1/token'): _token_json_handler(
                {'access_token': 'okta-at', 'token_type': 'Bearer', 'id_token': id_token}
            ),
            (host, 'GET', '/oauth2/v1/userinfo'): _json_handler(profile),
            (host, 'GET', '/oauth2/v1/keys'): json_response_handler(signing.jwks_document()),
        }
        return StrictProviderSpec(
            slug='okta',
            authorize_netloc=host,
            routes=routes,
            hostnames=[host],
            expected_uid=sub,
            company_host=host,
        )

    def _auth0_spec(self, *, base, client_id, sub, email, signing, token=None, profile_sub=None):
        host = urlparse(base).hostname
        iss = f'{base}/'
        id_token = token or self._signed(signing, iss=iss, aud=client_id, sub=sub, email=email)
        profile = {
            'sub': profile_sub or sub,
            'email': email,
            'email_verified': True,
            'name': 'Auth0 User',
        }
        routes = {
            (host, 'POST', '/oauth/token'): _token_json_handler(
                {'access_token': 'auth0-at', 'token_type': 'Bearer', 'id_token': id_token}
            ),
            (host, 'GET', '/userinfo'): _json_handler(profile),
            (host, 'GET', '/.well-known/jwks.json'): json_response_handler(signing.jwks_document()),
        }
        return StrictProviderSpec(
            slug='auth0',
            authorize_netloc=host,
            routes=routes,
            hostnames=[host],
            expected_uid=sub,
            company_host=host,
        )

    def _gitlab_spec(self, *, base, profile, capture=None):
        host = (urlparse(base).hostname or '').lower()
        routes = {
            (host, 'POST', '/oauth/token'): _token_json_handler(
                {'access_token': 'gitlab-at', 'token_type': 'Bearer'}
            ),
        }

        def _profile(http):
            if capture is not None:
                capture['path'] = http.path
                capture['authorization'] = http.headers.get('Authorization')
            _json_handler(profile)(http)

        routes[(host, 'GET', '/api/v4/user')] = _profile
        return StrictProviderSpec(
            slug='gitlab',
            authorize_netloc=host,
            routes=routes,
            hostnames=[host],
            expected_uid=str(profile['id']),
            company_host=host,
        )

    def _assert_missing_id_token(self, response):
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get('error_code'), 'oauth_id_token_missing')

    def test_okta_missing_id_token_rejects_callback(self):
        base = company_okta_base(self.company.slug)
        signing = generate_oauth_test_signing_key(kid='okta-missing')
        app, oauth_client = self._app(
            company=self.company,
            provider='okta',
            provider_id='',
            name='okta-missing',
            client_id='okta-missing-client',
            settings={'catalog_slug': 'okta', 'OKTA_BASE_URL': base},
        )
        spec = self._okta_spec(
            base=base,
            client_id=app.client_id,
            sub='okta-missing-sub',
            email='okta-missing@example.com',
            signing=signing,
        )
        host = urlparse(base).hostname
        spec.routes[(host, 'POST', '/oauth2/v1/token')] = _token_json_handler(
            {'access_token': 'okta-at', 'token_type': 'Bearer'}
        )
        before = User.objects.count()
        response = self._callback(slug='okta', spec=spec, oauth_client=oauth_client, company=self.company)
        self._assert_missing_id_token(response)
        self.assertEqual(User.objects.count(), before)

    def test_auth0_missing_id_token_rejects_callback(self):
        base = company_auth0_base(self.company.slug)
        signing = generate_oauth_test_signing_key(kid='auth0-missing')
        app, oauth_client = self._app(
            company=self.company,
            provider='auth0',
            provider_id='',
            name='auth0-missing',
            client_id='auth0-missing-client',
            settings={'catalog_slug': 'auth0', 'AUTH0_URL': base},
        )
        spec = self._auth0_spec(
            base=base,
            client_id=app.client_id,
            sub='auth0|missing',
            email='auth0-missing@example.com',
            signing=signing,
        )
        host = urlparse(base).hostname
        spec.routes[(host, 'POST', '/oauth/token')] = _token_json_handler(
            {'access_token': 'auth0-at', 'token_type': 'Bearer'}
        )
        before = User.objects.count()
        response = self._callback(slug='auth0', spec=spec, oauth_client=oauth_client, company=self.company)
        self._assert_missing_id_token(response)
        self.assertEqual(User.objects.count(), before)

    def test_keycloak_missing_id_token_rejects_callback(self):
        fixture = supported_provider_fixture('keycloak')
        signing = generate_oauth_test_signing_key(kid='kc-missing')
        oidc = company_keycloak_oidc(self.company.slug)
        app, oauth_client = self._app(
            company=self.company,
            provider='openid_connect',
            provider_id='keycloak',
            name='kc-missing',
            client_id='kc-missing-client',
            settings={'catalog_slug': 'keycloak', 'server_url': oidc.server_url},
        )
        spec = _build_oidc_strict_spec(
            slug='keycloak',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=dict(fixture.profile_document),
            signing=signing,
        )
        token_path = urlparse(f'{oidc.issuer}/token').path
        spec.routes[(oidc.hostname, 'POST', token_path)] = _token_json_handler(
            {'access_token': 'at-keycloak', 'token_type': 'Bearer'}
        )
        before = User.objects.count()
        response = self._callback(slug='keycloak', spec=spec, oauth_client=oauth_client, company=self.company)
        self._assert_missing_id_token(response)
        self.assertEqual(User.objects.count(), before)

    def test_keycloak_without_openid_scope_allows_missing_id_token(self):
        fixture = supported_provider_fixture('keycloak')
        signing = generate_oauth_test_signing_key(kid='kc-no-openid')
        oidc = company_keycloak_oidc(self.company.slug)
        app, oauth_client = self._app(
            company=self.company,
            provider='openid_connect',
            provider_id='keycloak',
            name='kc-no-openid',
            client_id='kc-no-openid-client',
            settings={
                'catalog_slug': 'keycloak',
                'server_url': oidc.server_url,
                'scope': ['profile', 'email'],
            },
        )
        spec = _build_oidc_strict_spec(
            slug='keycloak',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=dict(fixture.profile_document),
            signing=signing,
        )
        token_path = urlparse(f'{oidc.issuer}/token').path
        spec.routes[(oidc.hostname, 'POST', token_path)] = _token_json_handler(
            {'access_token': 'at-keycloak', 'token_type': 'Bearer'}
        )
        response = self._callback(slug='keycloak', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertTrue(
            SocialAccount.objects.filter(
                provider='keycloak', uid__endswith=f'|{fixture.expected_uid}'  # gitleaks:allow
            ).exists()
        )

    def test_okta_other_company_same_sub_does_not_sign_in_as_existing_user(self):
        base_a = company_okta_base(self.company.slug)
        base_b = company_okta_base(self.other.slug)
        sub = 'shared-okta-sub'
        SocialAccount.objects.create(
            provider='okta',
            uid=f'{base_a}|{sub}',
            user=self.victim,
            extra_data={},
        )
        signing = generate_oauth_test_signing_key(kid='okta-b')
        app, oauth_client = self._app(
            company=self.other,
            provider='okta',
            provider_id='',
            name='okta-b',
            client_id='okta-client-b',
            settings={'catalog_slug': 'okta', 'OKTA_BASE_URL': base_b},
        )
        spec = self._okta_spec(
            base=base_b,
            client_id=app.client_id,
            sub=sub,
            email='fresh-okta@example.com',
            signing=signing,
        )
        before = User.objects.count()
        response = self._callback(slug='okta', spec=spec, oauth_client=oauth_client, company=self.other)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertNotIn('shellui_oauth_error_code', response['Location'])
        intruder = SocialAccount.objects.get(provider='okta', uid=f'{base_b}|{sub}')
        self.assertNotEqual(intruder.user_id, self.victim.id)
        self.assertEqual(SocialAccount.objects.get(provider='okta', uid=f'{base_a}|{sub}').user_id, self.victim.id)
        self.assertEqual(User.objects.count(), before + 1)

    def test_auth0_other_company_same_sub_does_not_sign_in_as_existing_user(self):
        base_a = company_auth0_base(self.company.slug)
        base_b = company_auth0_base(self.other.slug)
        sub = 'shared-auth0-sub'
        SocialAccount.objects.create(
            provider='auth0',
            uid=f'{base_a}|{sub}',
            user=self.victim,
            extra_data={},
        )
        signing = generate_oauth_test_signing_key(kid='auth0-b')
        app, oauth_client = self._app(
            company=self.other,
            provider='auth0',
            provider_id='',
            name='auth0-b',
            client_id='auth0-client-b',
            settings={'catalog_slug': 'auth0', 'AUTH0_URL': base_b},
        )
        spec = self._auth0_spec(
            base=base_b,
            client_id=app.client_id,
            sub=sub,
            email='fresh-auth0@example.com',
            signing=signing,
        )
        response = self._callback(slug='auth0', spec=spec, oauth_client=oauth_client, company=self.other)
        self.assertEqual(response.status_code, 302, response.content)
        intruder = SocialAccount.objects.get(provider='auth0', uid=f'{base_b}|{sub}')
        self.assertNotEqual(intruder.user_id, self.victim.id)

    def test_self_hosted_gitlab_other_company_same_id_does_not_sign_in_as_existing_user(self):
        base_a = company_gitlab_url(self.company.slug)
        base_b = company_gitlab_url(self.other.slug)
        SocialAccount.objects.create(
            provider='gitlab',
            uid=f'{base_a}|4242',
            user=self.victim,
            extra_data={},
        )
        _app, oauth_client = self._app(
            company=self.other,
            provider='gitlab',
            provider_id='',
            name='gitlab-b',
            client_id='gitlab-client-b',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': base_b},
        )
        spec = self._gitlab_spec(
            base=base_b,
            profile={'id': 4242, 'username': 'b-user', 'name': 'B', 'email': 'b-user@example.com'},
        )
        response = self._callback(slug='gitlab', spec=spec, oauth_client=oauth_client, company=self.other)
        self.assertEqual(response.status_code, 302, response.content)
        intruder = SocialAccount.objects.get(provider='gitlab', uid=f'{base_b}|4242')
        self.assertNotEqual(intruder.user_id, self.victim.id)
        self.assertEqual(SocialAccount.objects.get(provider='gitlab', uid=f'{base_a}|4242').user_id, self.victim.id)

    def test_gitlab_com_unscoped_uid_still_signs_in(self):
        SocialAccount.objects.create(provider='gitlab', uid='4242', user=self.victim, extra_data={})
        _app, oauth_client = self._app(
            company=self.company,
            provider='gitlab',
            provider_id='',
            name='gitlab-com',
            client_id='gitlab-com-client',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': 'https://gitlab.com'},
        )
        spec = self._gitlab_spec(
            base='https://gitlab.com',
            profile={'id': 4242, 'username': 'dotcom', 'name': 'Dotcom', 'email': 'dotcom@example.com'},
        )
        before = User.objects.count()
        response = self._callback(slug='gitlab', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertNotIn('shellui_oauth_error_code', response['Location'])
        self.assertEqual(SocialAccount.objects.get(provider='gitlab', uid='4242').user_id, self.victim.id)
        self.assertEqual(User.objects.count(), before)

    def test_self_hosted_gitlab_email_conflict(self):
        base = company_gitlab_url(self.company.slug)
        _app, oauth_client = self._app(
            company=self.company,
            provider='gitlab',
            provider_id='',
            name='gitlab-conflict',
            client_id='gitlab-conflict-client',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': base},
        )
        capture = {}
        spec = self._gitlab_spec(
            base=base,
            profile={
                'id': 9991,
                'username': 'attacker',
                'name': 'Attacker',
                'email': 'victim@example.com',
                'email_verified': True,
            },
            capture=capture,
        )
        before = User.objects.count()
        response = self._callback(slug='gitlab', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get('error_code'), 'oauth_email_conflict')
        self.assertEqual(User.objects.count(), before)
        self.assertFalse(SocialAccount.objects.filter(provider='gitlab', uid__endswith='|9991').exists())
        self.assertTrue(str(capture.get('authorization') or '').startswith('Bearer '))
        self.assertNotIn('access_token', capture.get('path') or '')

    def test_okta_id_token_with_jti_signs_in(self):
        base = company_okta_base(self.company.slug)
        signing = generate_oauth_test_signing_key(kid='okta-jti')
        app, oauth_client = self._app(
            company=self.company,
            provider='okta',
            provider_id='',
            name='okta-jti',
            client_id='okta-jti-client',
            settings={'catalog_slug': 'okta', 'OKTA_BASE_URL': base},
        )
        spec = self._okta_spec(
            base=base,
            client_id=app.client_id,
            sub='okta-jti-sub',
            email='okta-jti@example.com',
            signing=signing,
        )
        response = self._callback(slug='okta', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertTrue(
            SocialAccount.objects.filter(provider='okta', uid=f'{base}|okta-jti-sub').exists()
        )

    def test_okta_wrong_signing_key_rejects_callback(self):
        base = company_okta_base(self.company.slug)
        trusted = generate_oauth_test_signing_key(kid='okta-trusted')
        wrong = generate_oauth_test_signing_key(kid='okta-wrong')
        app, oauth_client = self._app(
            company=self.company,
            provider='okta',
            provider_id='',
            name='okta-wrong-key',
            client_id='okta-wrong-client',
            settings={'catalog_slug': 'okta', 'OKTA_BASE_URL': base},
        )
        bad = self._signed(wrong, iss=base, aud=app.client_id, sub='okta-sub', email='okta@example.com')
        spec = self._okta_spec(
            base=base,
            client_id=app.client_id,
            sub='okta-sub',
            email='okta@example.com',
            signing=trusted,
            token=bad,
        )
        before = User.objects.count()
        response = self._callback(slug='okta', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get('error_code'), 'oauth_id_token_invalid')
        self.assertEqual(User.objects.count(), before)

    def test_auth0_wrong_signing_key_rejects_callback(self):
        base = company_auth0_base(self.company.slug)
        trusted = generate_oauth_test_signing_key(kid='auth0-trusted')
        wrong = generate_oauth_test_signing_key(kid='auth0-wrong')
        app, oauth_client = self._app(
            company=self.company,
            provider='auth0',
            provider_id='',
            name='auth0-wrong-key',
            client_id='auth0-wrong-client',
            settings={'catalog_slug': 'auth0', 'AUTH0_URL': base},
        )
        capture = {}
        bad = self._signed(wrong, iss=f'{base}/', aud=app.client_id, sub='auth0-sub', email='auth0@example.com')
        spec = self._auth0_spec(
            base=base,
            client_id=app.client_id,
            sub='auth0-sub',
            email='auth0@example.com',
            signing=trusted,
            token=bad,
        )

        def _capture(http):
            capture['path'] = http.path
            capture['authorization'] = http.headers.get('Authorization')
            _json_handler({'sub': 'auth0-sub', 'email': 'auth0@example.com', 'email_verified': True})(http)

        host = urlparse(base).hostname
        spec.routes[(host, 'GET', '/userinfo')] = _capture
        before = User.objects.count()
        response = self._callback(slug='auth0', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get('error_code'), 'oauth_id_token_invalid')
        self.assertEqual(User.objects.count(), before)

    def test_auth0_profile_uses_authorization_header(self):
        base = company_auth0_base(self.company.slug)
        signing = generate_oauth_test_signing_key(kid='auth0-header')
        app, oauth_client = self._app(
            company=self.company,
            provider='auth0',
            provider_id='',
            name='auth0-header',
            client_id='auth0-header-client',
            settings={'catalog_slug': 'auth0', 'AUTH0_URL': base},
        )
        capture = {}
        spec = self._auth0_spec(
            base=base,
            client_id=app.client_id,
            sub='auth0-header-sub',
            email='auth0-header@example.com',
            signing=signing,
        )

        def _capture(http):
            capture['path'] = http.path
            capture['authorization'] = http.headers.get('Authorization')
            _json_handler(
                {'sub': 'auth0-header-sub', 'email': 'auth0-header@example.com', 'email_verified': True, 'name': 'A'}
            )(http)

        host = urlparse(base).hostname
        spec.routes[(host, 'GET', '/userinfo')] = _capture
        response = self._callback(slug='auth0', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertTrue(str(capture.get('authorization') or '').startswith('Bearer '))
        self.assertNotIn('access_token', capture.get('path') or '')

    def test_keycloak_id_token_jti_signs_in_once(self):
        fixture = supported_provider_fixture('keycloak')
        signing = generate_oauth_test_signing_key(kid='kc-jti')
        oidc = company_keycloak_oidc(self.company.slug)
        app, oauth_client = self._app(
            company=self.company,
            provider='openid_connect',
            provider_id='keycloak',
            name='kc-jti',
            client_id='kc-jti-client',
            settings={'catalog_slug': 'keycloak', 'server_url': oidc.server_url},
        )
        profile = dict(fixture.profile_document)
        spec = _build_oidc_strict_spec(
            slug='keycloak',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            signing=signing,
        )
        token = self._signed(
            signing,
            iss=oidc.issuer,
            aud=app.client_id,
            sub=fixture.expected_uid,
            email=profile['email'],
            jti='keycloak-jti-once',
        )
        token_path = urlparse(f'{oidc.issuer}/token').path
        spec.routes[(oidc.hostname, 'POST', token_path)] = _token_json_handler(
            {'access_token': 'at-keycloak', 'token_type': 'Bearer', 'id_token': token}
        )
        response = self._callback(slug='keycloak', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertTrue(
            SocialAccount.objects.filter(provider='keycloak', uid=f'{oidc.issuer}|{fixture.expected_uid}').exists()
        )

    def test_keycloak_userinfo_sub_mismatch_rejects_callback(self):
        fixture = supported_provider_fixture('keycloak')
        signing = generate_oauth_test_signing_key(kid='kc-sub')
        oidc = company_keycloak_oidc(self.company.slug)
        app, oauth_client = self._app(
            company=self.company,
            provider='openid_connect',
            provider_id='keycloak',
            name='kc-sub',
            client_id='kc-sub-client',
            settings={'catalog_slug': 'keycloak', 'server_url': oidc.server_url},
        )
        profile = dict(fixture.profile_document)
        profile['sub'] = 'not-the-token-sub'
        spec = _build_oidc_strict_spec(
            slug='keycloak',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            signing=signing,
        )
        before = User.objects.count()
        response = self._callback(slug='keycloak', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get('error_code'), 'oauth_subject_mismatch')
        self.assertEqual(User.objects.count(), before)

    def test_keycloak_userinfo_without_sub_rejects_callback(self):
        fixture = supported_provider_fixture('keycloak')
        signing = generate_oauth_test_signing_key(kid='kc-no-sub')
        oidc = company_keycloak_oidc(self.company.slug)
        app, oauth_client = self._app(
            company=self.company,
            provider='openid_connect',
            provider_id='keycloak',
            name='kc-no-sub',
            client_id='kc-no-sub-client',
            settings={'catalog_slug': 'keycloak', 'server_url': oidc.server_url},
        )
        profile = dict(fixture.profile_document)
        profile.pop('sub', None)
        profile['id'] = 'decoy-keycloak-id'
        profile['mail'] = 'decoy-mail@example.com'
        spec = _build_oidc_strict_spec(
            slug='keycloak',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            signing=signing,
        )
        before = User.objects.count()
        response = self._callback(slug='keycloak', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get('error_code'), 'oauth_subject_mismatch')
        self.assertEqual(User.objects.count(), before)
        self.assertFalse(SocialAccount.objects.filter(uid__contains='decoy-keycloak-id').exists())
        self.assertFalse(SocialAccount.objects.filter(uid__contains='decoy-mail@example.com').exists())

    def test_keycloak_userinfo_id_field_without_sub_rejects_callback(self):
        fixture = supported_provider_fixture('keycloak')
        signing = generate_oauth_test_signing_key(kid='kc-id-uid')
        oidc = company_keycloak_oidc(self.company.slug)
        app, oauth_client = self._app(
            company=self.company,
            provider='openid_connect',
            provider_id='keycloak',
            name='kc-id-uid',
            client_id='kc-id-uid-client',
            settings={
                'catalog_slug': 'keycloak',
                'server_url': oidc.server_url,
                'uid_field': 'id',
            },
        )
        profile = dict(fixture.profile_document)
        profile.pop('sub', None)
        profile['id'] = 'decoy-keycloak-id'
        profile['mail'] = 'decoy-mail@example.com'
        spec = _build_oidc_strict_spec(
            slug='keycloak',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            signing=signing,
        )
        before = User.objects.count()
        response = self._callback(slug='keycloak', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get('error_code'), 'oauth_subject_mismatch')
        self.assertEqual(User.objects.count(), before)
        self.assertFalse(SocialAccount.objects.filter(provider='keycloak', uid__contains='decoy-keycloak-id').exists())

    def test_returning_uid_signs_in_when_email_belongs_to_someone_else(self):
        fixture = supported_provider_fixture('keycloak')
        signing = generate_oauth_test_signing_key(kid='kc-return')
        oidc = company_keycloak_oidc(self.company.slug)
        alice = User.objects.create_user(username='alice-return', email='alice-return@example.com', password='x')
        other = User.objects.create_user(username='bob-email', email=fixture.profile_document['email'], password='x')
        SocialAccount.objects.create(
            provider='keycloak',
            uid=f'{oidc.issuer}|{fixture.expected_uid}',
            user=alice,
            extra_data={},
        )
        app, oauth_client = self._app(
            company=self.company,
            provider='openid_connect',
            provider_id='keycloak',
            name='kc-return',
            client_id='kc-return-client',
            settings={'catalog_slug': 'keycloak', 'server_url': oidc.server_url},
        )
        spec = _build_oidc_strict_spec(
            slug='keycloak',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=dict(fixture.profile_document),
            signing=signing,
        )
        before = User.objects.count()
        response = self._callback(slug='keycloak', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertNotIn('shellui_oauth_error_code', response['Location'])
        account = SocialAccount.objects.get(provider='keycloak', uid=f'{oidc.issuer}|{fixture.expected_uid}')
        self.assertEqual(account.user_id, alice.id)
        self.assertNotEqual(account.user_id, other.id)
        self.assertEqual(User.objects.count(), before)

    def test_domain_join_ignores_unverified_email(self):
        self.company.access_mode = Company.ACCESS_DOMAIN
        self.company.allowed_email_domains = ['example.com']
        self.company.save(update_fields=['access_mode', 'allowed_email_domains'])
        fixture = supported_provider_fixture('keycloak')
        signing = generate_oauth_test_signing_key(kid='kc-domain')
        oidc = company_keycloak_oidc(self.company.slug)
        app, oauth_client = self._app(
            company=self.company,
            provider='openid_connect',
            provider_id='keycloak',
            name='kc-domain',
            client_id='kc-domain-client',
            settings={'catalog_slug': 'keycloak', 'server_url': oidc.server_url},
        )
        spec = _build_oidc_strict_spec(
            slug='keycloak',
            company_slug=self.company.slug,
            social_app=app,
            fixture_expected_uid=fixture.expected_uid,
            profile=dict(fixture.profile_document),
            signing=signing,
        )
        response = self._callback(slug='keycloak', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertIn('shellui_oauth_error_code=access_denied', response['Location'])
        account = SocialAccount.objects.get(
            provider='keycloak', uid__endswith=f'|{fixture.expected_uid}'  # gitleaks:allow
        )
        membership = CompanyMembership.objects.get(company=self.company, user=account.user)
        self.assertFalse(membership.is_enabled)

    def test_domain_join_accepts_verified_email(self):
        self.company.access_mode = Company.ACCESS_DOMAIN
        self.company.allowed_email_domains = ['example.com']
        self.company.save(update_fields=['access_mode', 'allowed_email_domains'])
        app, oauth_client = self._app(
            company=self.company,
            provider='slack',
            provider_id='',
            name='slack-domain',
            client_id='slack-domain-client',
            settings={'catalog_slug': 'slack'},
        )
        request = RequestFactory().get('/')
        request.session = {}
        spec = build_strict_spec(
            slug='slack',
            request=request,
            social_app=app,
            company_slug=self.company.slug,
        )
        response = self._callback(slug='slack', spec=spec, oauth_client=oauth_client, company=self.company)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertNotIn('shellui_oauth_error_code', response['Location'])
        account = SocialAccount.objects.get(provider='slack')
        membership = CompanyMembership.objects.get(company=self.company, user=account.user)
        self.assertTrue(membership.is_enabled)

    def test_gitlab_uid_migration_scopes_self_hosted_and_keeps_gitlab_com(self):
        user = User.objects.create_user(username='gl-mig', email='gl-mig@example.com', password='x')
        dotcom = SocialApp.objects.create(
            provider='gitlab',
            name='gl-mig-com',
            client_id='gl-mig-com',
            secret='secret',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': 'https://gitlab.com'},
        )
        hosted = SocialApp.objects.create(
            provider='gitlab',
            name='gl-mig-hosted',
            client_id='gl-mig-hosted',
            secret='secret',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': 'https://gitlab.mig.example.com'},
        )
        com_account = SocialAccount.objects.create(provider='gitlab', uid='42', user=user, extra_data={})
        hosted_account = SocialAccount.objects.create(provider='gitlab', uid='77', user=user, extra_data={})
        SocialToken.objects.create(app=dotcom, account=com_account, token='t1')
        SocialToken.objects.create(app=hosted, account=hosted_account, token='t2')
        _gitlab_migration.forwards(apps, None)
        com_account.refresh_from_db()
        hosted_account.refresh_from_db()
        self.assertEqual(com_account.uid, '42')
        self.assertEqual(hosted_account.uid, 'https://gitlab.mig.example.com|77')

    def test_gitlab_uid_migration_scopes_account_without_token(self):
        user = User.objects.create_user(username='gl-notoken', email='gl-notoken@example.com', password='x')
        CompanyMembership.objects.create(company=self.company, user=user, is_enabled=True)
        base = 'https://gitlab.notoken.example.com'
        self._app(
            company=self.company,
            provider='gitlab',
            provider_id='',
            name='gl-notoken',
            client_id='gl-notoken',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': base},
        )
        account = SocialAccount.objects.create(provider='gitlab', uid='77', user=user, extra_data={})
        self.assertFalse(SocialToken.objects.filter(account=account).exists())
        _gitlab_migration.forwards(apps, None)
        account.refresh_from_db()
        self.assertEqual(account.uid, f'{base}|77')

    def test_gitlab_uid_migration_is_idempotent(self):
        user = User.objects.create_user(username='gl-again', email='gl-again@example.com', password='x')
        CompanyMembership.objects.create(company=self.company, user=user, is_enabled=True)
        base = 'https://gitlab.again.example.com'
        self._app(
            company=self.company,
            provider='gitlab',
            provider_id='',
            name='gl-again',
            client_id='gl-again',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': base},
        )
        account = SocialAccount.objects.create(provider='gitlab', uid='88', user=user, extra_data={})
        _gitlab_migration.forwards(apps, None)
        _gitlab_migration.forwards(apps, None)
        account.refresh_from_db()
        self.assertEqual(account.uid, f'{base}|88')

    def test_gitlab_uid_migration_ambiguous_row_fails(self):
        user = User.objects.create_user(username='gl-ambiguous', email='gl-ambiguous@example.com', password='x')
        CompanyMembership.objects.create(company=self.company, user=user, is_enabled=True)
        CompanyMembership.objects.create(company=self.other, user=user, is_enabled=True)
        self._app(
            company=self.company,
            provider='gitlab',
            provider_id='',
            name='gl-ambiguous-com',
            client_id='gl-ambiguous-com',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': 'https://gitlab.com'},
        )
        self._app(
            company=self.other,
            provider='gitlab',
            provider_id='',
            name='gl-ambiguous-hosted',
            client_id='gl-ambiguous-hosted',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': 'https://gitlab.other.example.com'},
        )
        account = SocialAccount.objects.create(provider='gitlab', uid='77', user=user, extra_data={})
        with self.assertRaises(_gitlab_migration.GitlabUidMigrationError) as ctx:
            _gitlab_migration.forwards(apps, None)
        self.assertIn(str(account.id), str(ctx.exception))
        account.refresh_from_db()
        self.assertEqual(account.uid, '77')

    def test_gitlab_uid_migration_rejects_pipe_too_long_and_collision(self):
        user = User.objects.create_user(username='gl-bad', email='gl-bad@example.com', password='x')
        CompanyMembership.objects.create(company=self.company, user=user, is_enabled=True)
        base = 'https://gitlab.bad.example.com'
        self._app(
            company=self.company,
            provider='gitlab',
            provider_id='',
            name='gl-bad',
            client_id='gl-bad',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': base},
        )
        piped = SocialAccount.objects.create(provider='gitlab', uid='already|scoped', user=user, extra_data={})
        with self.assertRaises(_gitlab_migration.GitlabUidMigrationError) as ctx:
            _gitlab_migration.forwards(apps, None)
        self.assertIn(str(piped.id), str(ctx.exception))
        piped.refresh_from_db()
        self.assertEqual(piped.uid, 'already|scoped')

        piped.uid = 'x' * 180
        piped.save(update_fields=['uid'])
        with self.assertRaises(_gitlab_migration.GitlabUidMigrationError) as ctx:
            _gitlab_migration.forwards(apps, None)
        self.assertIn(str(piped.id), str(ctx.exception))
        piped.refresh_from_db()
        self.assertEqual(piped.uid, 'x' * 180)

        piped.uid = '77'
        piped.save(update_fields=['uid'])
        other = User.objects.create_user(username='gl-taken', email='gl-taken@example.com', password='x')
        SocialAccount.objects.create(provider='gitlab', uid=f'{base}|77', user=other, extra_data={})
        with self.assertRaises(_gitlab_migration.GitlabUidMigrationError) as ctx:
            _gitlab_migration.forwards(apps, None)
        self.assertIn(str(piped.id), str(ctx.exception))
        piped.refresh_from_db()
        self.assertEqual(piped.uid, '77')

    def test_scope_gitlab_command_binds_ambiguous_account(self):
        user = User.objects.create_user(username='gl-bind', email='gl-bind@example.com', password='x')
        CompanyMembership.objects.create(company=self.company, user=user, is_enabled=True)
        CompanyMembership.objects.create(company=self.other, user=user, is_enabled=True)
        self._app(
            company=self.company,
            provider='gitlab',
            provider_id='',
            name='gl-bind-com',
            client_id='gl-bind-com',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': 'https://gitlab.com'},
        )
        hosted, _oauth_client = self._app(
            company=self.other,
            provider='gitlab',
            provider_id='',
            name='gl-bind-hosted',
            client_id='gl-bind-hosted',
            settings={'catalog_slug': 'gitlab', 'gitlab_url': 'https://gitlab.bind.example.com'},
        )
        account = SocialAccount.objects.create(provider='gitlab', uid='77', user=user, extra_data={})
        call_command('scope_gitlab_social_uids', account_id=account.id, social_app_id=hosted.id)
        _gitlab_migration.forwards(apps, None)
        account.refresh_from_db()
        self.assertEqual(account.uid, 'https://gitlab.bind.example.com|77')
