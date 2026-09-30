"""Google OAuth callback must verify id_token JWKS before email linking (no verify_and_decode stubs)."""

from __future__ import annotations

import time

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.oauth_state import OAUTH_STATE_NONCE_COOKIE, build_oauth_state, parse_oauth_state
from apps.authapi.tests.oauth_ssrf_test_utils import pin_oauth_http_to_localhost
from apps.authapi.tests.oauth_strict_harness import _token_json_handler
from apps.authapi.tests.oauth_test_crypto import (
    OAuthMockHttpsServer,
    generate_oauth_test_signing_key,
    json_response_handler,
)
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect

User = get_user_model()


def _google_mock_routes(*, client_id: str, signing, sub: str, email: str, issuer: str, audience: str | None = None):
    now = int(time.time())
    aud = audience if audience is not None else client_id
    id_token = signing.sign_rs256(
        {
            'iss': issuer,
            'aud': aud,
            'sub': sub,
            'email': email,
            'email_verified': True,
            'exp': now + 3600,
            'iat': now,
        }
    )
    routes = {
        ('oauth2.googleapis.com', 'POST', '/token'): _token_json_handler(
            {'access_token': 'google-at', 'token_type': 'Bearer', 'id_token': id_token}
        ),
        ('www.googleapis.com', 'GET', '/oauth2/v3/certs'): json_response_handler(signing.jwks_document()),
        ('www.googleapis.com', 'GET', '/oauth2/v1/certs'): json_response_handler(signing.google_certs_document()),
    }
    hostnames = ['oauth2.googleapis.com', 'www.googleapis.com']
    return routes, hostnames, id_token


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
    AUTH_RATE_LIMIT_ENABLED=False,
    OAUTH_TOKEN_DELIVERY='code',
    OAUTH_SKIP_CONFIRM_PROVIDERS=['google'],
)
class GoogleIdTokenCallbackTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Google JWKS Co', slug='google-jwks-co')
        self.client_id = 'google-jwks-client'
        self.signing = generate_oauth_test_signing_key(kid='google-callback-kid')
        self.google_app = SocialApp.objects.create(
            provider='google',
            name='Google JWKS',
            client_id=self.client_id,
            secret='gsecret',
            settings={'catalog_slug': 'google', 'created_by_company_id': self.company.id},
        )
        self.oauth_client = CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.google_app,
            is_active=True,
        )
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )
        self.existing = User.objects.create_user(
            username='google-existing',
            email='user-google@example.com',
            password='unused',
        )

    def _callback_with_routes(self, routes, hostnames):
        redirect_to = 'https://shell.example.com/login/callback'
        state, _nonce = build_oauth_state(
            provider='google',
            redirect_to=redirect_to,
            company_id=self.company.id,
            company_oauth_client_id=self.oauth_client.id,
        )
        payload, err = parse_oauth_state(state)
        self.assertIsNone(err)
        assert payload is not None
        server = OAuthMockHttpsServer.start(hostnames=hostnames, routes=routes)
        host_ports = [(host, server.port) for host in hostnames]
        try:
            from unittest.mock import patch

            with pin_oauth_http_to_localhost(*host_ports):
                with patch(
                    'apps.actions.webhook_transport.ssl.create_default_context',
                    return_value=server.ssl_client_context(),
                ):
                    self.client.cookies[OAUTH_STATE_NONCE_COOKIE] = payload['nonce']
                    return self.client.get(
                        '/api/v1/oauth/callback',
                        {'code': 'auth-code', 'state': state},
                    )
        finally:
            server.shutdown()

    def test_verified_id_token_links_existing_user_on_callback(self):
        routes, hostnames, _token = _google_mock_routes(
            client_id=self.client_id,
            signing=self.signing,
            sub='google-sub-001',
            email='user-google@example.com',
            issuer='https://accounts.google.com',
        )
        response = self._callback_with_routes(routes, hostnames)
        self.assertEqual(response.status_code, 302)
        self.existing.refresh_from_db()
        self.assertFalse(User.objects.filter(email='user-google@example.com').exclude(pk=self.existing.pk).exists())

    def test_wrong_issuer_id_token_rejects_callback(self):
        routes, hostnames, _token = _google_mock_routes(
            client_id=self.client_id,
            signing=self.signing,
            sub='google-sub-001',
            email='user-google@example.com',
            issuer='https://evil-issuer.example.com',
        )
        before = User.objects.count()
        response = self._callback_with_routes(routes, hostnames)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(User.objects.count(), before)

    def test_wrong_audience_id_token_rejects_callback(self):
        routes, hostnames, _token = _google_mock_routes(
            client_id=self.client_id,
            signing=self.signing,
            sub='google-sub-001',
            email='user-google@example.com',
            issuer='https://accounts.google.com',
            audience='other-client-id',
        )
        before = User.objects.count()
        response = self._callback_with_routes(routes, hostnames)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(User.objects.count(), before)

    def test_wrong_signing_key_id_token_rejects_callback(self):
        wrong_key = generate_oauth_test_signing_key(kid='google-wrong-kid')
        routes, hostnames, _token = _google_mock_routes(
            client_id=self.client_id,
            signing=wrong_key,
            sub='google-sub-001',
            email='user-google@example.com',
            issuer='https://accounts.google.com',
        )
        routes[('www.googleapis.com', 'GET', '/oauth2/v3/certs')] = json_response_handler(
            self.signing.jwks_document()
        )
        routes[('www.googleapis.com', 'GET', '/oauth2/v1/certs')] = json_response_handler(
            wrong_key.google_certs_document()
        )
        before = User.objects.count()
        response = self._callback_with_routes(routes, hostnames)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(User.objects.count(), before)
        body = response.json()
        self.assertEqual(body.get('error_code'), 'oauth_id_token_invalid')
