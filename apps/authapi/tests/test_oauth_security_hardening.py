"""Security review tests (H2-H3, M1, ContextVar) without stubbing jwtkit.verify_and_decode."""

from __future__ import annotations

import time
import uuid
from unittest.mock import patch

from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings

from apps.authapi.oauth_allauth import build_allauth_authorize_url
from apps.authapi.oauth_id_token import verify_apple_id_token_for_bridge, verified_login_id_token_claims
from apps.authapi.oauth_request_context import get_bound_oauth_social_app, oauth_allauth_request
from apps.authapi.oauth_social_account import bind_oauth_social_app, get_bound_oauth_social_app as bound_from_request
from apps.authapi.oauth_state import build_oauth_state, consume_apple_form_post_state_once
from apps.authapi.oauth_user import extract_oauth_profile, microsoft_email_trustworthy
from apps.authapi.provider_registry import get_provider_catalog
from apps.authapi.tests.oauth_ssrf_test_utils import pin_oauth_http_to_localhost
from apps.authapi.tests.oauth_test_crypto import (
    OAuthMockHttpsServer,
    generate_apple_test_signing_key,
    generate_oauth_test_signing_key,
    json_response_handler,
)
from apps.authapi.views import ShellUIOAuthCallbackView
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect


@override_settings(
    SECRET_KEY='test-secret',
    DEBUG=True,
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
)
class OAuthSecurityHardeningTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.site = Site.objects.get_current()
        self.company = Company.objects.create(name='Sec Co', slug='sec-co')
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )

    def test_contextvar_cleared_after_oauth_allauth_request(self):
        app = SocialApp.objects.create(provider='github', name='gh', client_id='cid', secret='sec')
        request = self.factory.get('/')
        bind_oauth_social_app(request, app)
        self.assertIs(bound_from_request(request), app)
        self.assertIsNone(get_bound_oauth_social_app())
        with oauth_allauth_request(request, social_app=app):
            self.assertIs(get_bound_oauth_social_app(), app)
        self.assertIsNone(get_bound_oauth_social_app())

    def test_bind_oauth_social_app_does_not_touch_contextvar(self):
        app = SocialApp.objects.create(provider='github', name='gh2', client_id='c2', secret='s')
        request = self.factory.get('/')
        bind_oauth_social_app(request, app)
        self.assertIsNone(get_bound_oauth_social_app())

    def test_microsoft_tid_compared_only_for_guid_tenant(self):
        guid = '11111111-1111-1111-1111-111111111111'
        self.assertTrue(
            microsoft_email_trustworthy(
                tenant=guid,
                configured_tenant=guid,
                id_token_claims={'tid': guid, 'xms_edov': False},
            )
        )
        self.assertFalse(
            microsoft_email_trustworthy(
                tenant=guid,
                configured_tenant=guid,
                id_token_claims={'tid': '22222222-2222-2222-2222-222222222222', 'xms_edov': True},
            )
        )
        with patch('apps.authapi.oauth_id_token.microsoft_tenant_guid_for_domain', return_value=None):
            self.assertFalse(
                microsoft_email_trustworthy(
                    tenant='contoso.onmicrosoft.com',
                    configured_tenant='contoso.onmicrosoft.com',
                    id_token_claims={'tid': 'different-guid', 'xms_edov': True},
                )
            )

    def test_microsoft_extract_oauth_profile_domain_tenant_requires_matching_tid(self):
        entry = get_provider_catalog().by_slug()['microsoft']
        domain = 'contoso.onmicrosoft.com'
        expected_tid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        userinfo = {
            'id': 'ms-user-id',
            'mail': 'user@contoso.com',
            'userPrincipalName': 'user@contoso.com',
        }
        with patch(
            'apps.authapi.oauth_id_token.microsoft_tenant_guid_for_domain',
            return_value=expected_tid,
        ):
            profile, err = extract_oauth_profile(
                'microsoft',
                userinfo,
                'access-token',
                tenant=domain,
                id_token_claims={'tid': expected_tid},
                catalog_entry=entry,
            )
            self.assertIsNone(err)
            self.assertTrue(profile.email_verified_for_link)

            profile, err = extract_oauth_profile(
                'microsoft',
                userinfo,
                'access-token',
                tenant=domain,
                id_token_claims={'tid': 'wrong-tenant-guid'},
                catalog_entry=entry,
            )
            self.assertIsNone(profile)
            self.assertIn('tenant', (err or '').lower())

            profile, err = extract_oauth_profile(
                'microsoft',
                userinfo,
                'access-token',
                tenant=domain,
                id_token_claims={},
                catalog_entry=entry,
            )
            self.assertIsNone(profile)
            self.assertIn('verified id token', (err or '').lower())

    def test_microsoft_domain_tid_lookup_failure_is_cached(self):
        from apps.authapi import oauth_id_token as ms_id_token

        ms_id_token._microsoft_domain_tid_cache.clear()
        domain = 'missing.onmicrosoft.com'
        with patch('apps.authapi.oauth_id_token.fetch_oidc_discovery', side_effect=OSError('offline')):
            self.assertIsNone(ms_id_token.microsoft_tenant_guid_for_domain(domain))
            self.assertEqual(ms_id_token.fetch_oidc_discovery.call_count, 1)
            self.assertIsNone(ms_id_token.microsoft_tenant_guid_for_domain(domain))
            self.assertEqual(ms_id_token.fetch_oidc_discovery.call_count, 1)

    def test_microsoft_jwks_verification_uses_common_keys_and_tenant_guid_issuer(self):
        signing = generate_oauth_test_signing_key(kid='ms-kid')
        hostname = 'login.microsoftonline.com'
        tenant_guid = str(uuid.uuid4())
        issuer = f'https://login.microsoftonline.com/{tenant_guid}/v2.0'
        server = OAuthMockHttpsServer.start(
            hostnames=[hostname],
            routes={
                (hostname, 'GET', '/common/discovery/v2.0/keys'): json_response_handler(
                    signing.jwks_document()
                ),
            },
        )
        client_id = 'ms-client-id'
        now = int(time.time())
        token = signing.sign_rs256(
            {
                'iss': issuer,
                'aud': client_id,
                'sub': 'user-sub',
                'tid': tenant_guid,
                'exp': now + 3600,
                'iat': now,
            }
        )
        app = SocialApp(provider='microsoft', client_id=client_id, secret='s', settings={'tenant': tenant_guid})
        entry = get_provider_catalog().by_slug()['microsoft']
        keys_url = f'https://{hostname}:{server.port}/common/discovery/v2.0/keys'
        try:
            with pin_oauth_http_to_localhost((hostname, server.port)):
                with patch('apps.authapi.oauth_id_token.MICROSOFT_JWKS_URL', keys_url):
                    with patch(
                        'apps.actions.webhook_transport.ssl.create_default_context',
                        return_value=server.ssl_client_context(),
                    ):
                        claims = verified_login_id_token_claims(
                            entry=entry,
                            social_app=app,
                            id_token_raw=token,
                            userinfo={},
                        )
            self.assertEqual(claims.get('tid'), tenant_guid)
        finally:
            server.shutdown()

    def test_unsigned_jwt_rejected_for_login_claims(self):
        entry = get_provider_catalog().by_slug()['microsoft']
        app = SocialApp(provider='microsoft', client_id='cid', secret='s')
        unsigned = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.'
        claims = verified_login_id_token_claims(
            entry=entry,
            social_app=app,
            id_token_raw=unsigned,
            userinfo={'_verified_id_token_claims': {'tid': 'evil'}},
        )
        self.assertEqual(claims, {})

    def test_oidc_discovery_jwks_and_issuer_used_for_verification(self):
        signing = generate_oauth_test_signing_key(kid='oidc-kid')
        hostname = 'issuer.example.com'
        issuer = f'https://{hostname}'
        discovery = {
            'issuer': issuer,
            'jwks_uri': f'{issuer}/jwks',
            'authorization_endpoint': f'{issuer}/authorize',
            'token_endpoint': f'{issuer}/token',
            'userinfo_endpoint': f'{issuer}/userinfo',
        }
        server = OAuthMockHttpsServer.start(
            hostnames=[hostname],
            routes={
                (hostname, 'GET', '/.well-known/openid-configuration'): json_response_handler(discovery),
                (hostname, 'GET', '/jwks'): json_response_handler(signing.jwks_document()),
            },
        )
        client_id = 'oidc-client'
        now = int(time.time())
        token = signing.sign_rs256(
            {
                'iss': issuer,
                'aud': client_id,
                'sub': 'oidc-sub',
                'email': 'user@example.com',
                'email_verified': True,
                'exp': now + 3600,
                'iat': now,
            }
        )
        app = SocialApp(
            provider='openid_connect',
            provider_id='tenant-a',
            client_id=client_id,
            secret='s',
            settings={
                'catalog_slug': 'keycloak',
                'server_url': f'{issuer}/.well-known/openid-configuration',
            },
        )
        entry = get_provider_catalog().by_slug()['keycloak']
        try:
            with pin_oauth_http_to_localhost((hostname, server.port)):
                with patch(
                    'apps.actions.webhook_transport.ssl.create_default_context',
                    return_value=server.ssl_client_context(),
                ):
                    claims = verified_login_id_token_claims(
                        entry=entry,
                        social_app=app,
                        id_token_raw=token,
                        userinfo={},
                    )
            self.assertEqual(claims.get('iss'), issuer)
            profile, err = extract_oauth_profile(
                'keycloak',
                {'email': 'user@example.com', 'sub': 'oidc-sub'},
                'access',
                id_token_claims=claims,
                catalog_entry=entry,
            )
            self.assertIsNone(err)
            assert profile is not None
            self.assertFalse(profile.email_verified_for_link)
        finally:
            server.shutdown()

    def test_verify_apple_id_token_for_bridge_es256_local_jwks(self):
        signing = generate_apple_test_signing_key()
        hostname = 'appleid.apple.com'
        server = OAuthMockHttpsServer.start(
            hostnames=[hostname],
            routes={(hostname, 'GET', '/auth/keys'): json_response_handler(signing.jwks_document())},
        )
        client_id = 'apple-bridge-client'
        nonce = 'bridge-nonce-es256'
        now = int(time.time())
        token = signing.sign_es256(
            {
                'iss': 'https://appleid.apple.com',
                'aud': client_id,
                'sub': 'apple-user-sub',
                'nonce': nonce,
                'exp': now + 3600,
                'iat': now,
            }
        )
        app = SocialApp.objects.create(
            provider='apple',
            name='apple-jwks',
            client_id=client_id,
            secret='sec',
            key='TEAM',
            settings={'catalog_slug': 'apple'},
        )
        app.sites.add(self.site)
        request = self.factory.get('/')
        keys_url = f'https://{hostname}:{server.port}/auth/keys'
        try:
            with pin_oauth_http_to_localhost((hostname, server.port)):
                with patch(
                    'allauth.socialaccount.providers.apple.views.AppleOAuth2Adapter.public_key_url',
                    keys_url,
                ):
                    with patch(
                        'apps.actions.webhook_transport.ssl.create_default_context',
                        return_value=server.ssl_client_context(),
                    ):
                        claims = verify_apple_id_token_for_bridge(
                            request,
                            social_app=app,
                            id_token=token,
                            expected_nonce=nonce,
                        )
            self.assertEqual(claims.get('sub'), 'apple-user-sub')
        finally:
            server.shutdown()

    def test_apple_authorize_url_includes_nonce(self):
        app = SocialApp.objects.create(
            provider='apple',
            name='apple',
            client_id='apple-client',
            secret='kid-secret',
            key='TEAM',
            settings={'catalog_slug': 'apple', 'certificate_key': 'unused-in-url-test'},
        )
        app.sites.add(self.site)
        CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        request = self.factory.get('/api/v1/authorize')
        request.session = {}
        nonce = 'nonce-abc-123'
        entry = get_provider_catalog().by_slug()['apple']
        url = build_allauth_authorize_url(
            request,
            entry=entry,
            social_app=app,
            redirect_uri='https://auth.example.com/api/v1/oauth/callback',
            state='signed-state',
            oauth_nonce=nonce,
        )
        self.assertIn(f'nonce={nonce}', url)

    def test_apple_form_post_state_not_consumed_until_bridge_succeeds(self):
        app = SocialApp.objects.create(
            provider='apple',
            name='apple-bridge',
            client_id='apple-client',
            secret='sec',
            key='TEAM',
            settings={'catalog_slug': 'apple', 'created_by_company_id': self.company.id},
        )
        app.sites.add(self.site)
        client = CompanyOAuthClient.objects.create(company=self.company, social_app=app, is_active=True)
        state, _nonce = build_oauth_state(
            provider='apple',
            redirect_to='https://shell.example.com/cb',
            company_id=self.company.id,
            company_oauth_client_id=client.id,
        )
        cache.clear()
        request = self.factory.post(
            '/api/v1/oauth/callback',
            {'code': 'c', 'state': state, 'id_token': 'not-a-valid-jwt'},
        )
        response = ShellUIOAuthCallbackView.as_view()(request)
        self.assertNotEqual(response.status_code, 303)
        self.assertTrue(consume_apple_form_post_state_once(state))
