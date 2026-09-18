"""Production-safe JWT/CORS defaults (issue #10)."""

from django.test import Client, SimpleTestCase, TestCase, override_settings
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.exceptions import InvalidToken

from apps.authapi.authentication import ShellUIJWTAuthentication
from apps.authapi.checks import (
    cors_allow_all_forbidden_in_production,
    jwt_hs256_legacy_disabled_in_production,
    jwt_issuer_audience_required_in_production,
)
from apps.authapi.jwks import generate_rsa_key_pair, resolve_jwt_configuration


class JwtLegacyDefaultTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.private_pem, cls.public_pem = generate_rsa_key_pair(key_size=2048)

    def test_rs256_production_defaults_hs256_legacy_off(self):
        config = resolve_jwt_configuration(
            secret_key='secret',
            debug=False,
            private_key_pem=self.private_pem,
            public_key_pem=self.public_pem,
        )
        self.assertEqual(config['algorithm'], 'RS256')
        self.assertFalse(config['accept_hs256_legacy'])

    def test_rs256_debug_defaults_hs256_legacy_on_for_migration(self):
        config = resolve_jwt_configuration(
            secret_key='secret',
            debug=True,
            private_key_pem=self.private_pem,
            public_key_pem=self.public_pem,
        )
        self.assertTrue(config['accept_hs256_legacy'])

    def test_rs256_explicit_legacy_false(self):
        config = resolve_jwt_configuration(
            secret_key='secret',
            debug=True,
            private_key_pem=self.private_pem,
            public_key_pem=self.public_pem,
            accept_hs256_legacy=False,
        )
        self.assertFalse(config['accept_hs256_legacy'])


class Hs256LegacyRejectedTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.private_pem, cls.public_pem = generate_rsa_key_pair(key_size=2048)
        cls.secret_key = 'unit-test-secret-key-not-for-production'

    def test_hs256_token_rejected_when_legacy_disabled(self):
        hs256_backend = TokenBackend(
            algorithm='HS256',
            signing_key=self.secret_key,
            verifying_key=self.secret_key,
        )
        raw = hs256_backend.encode({'token_type': 'access', 'exp': 9999999999})

        with override_settings(
            SECRET_KEY=self.secret_key,
            JWT_ALGORITHM='RS256',
            JWT_ACCEPT_HS256_LEGACY=False,
            SIMPLE_JWT={
                'ALGORITHM': 'RS256',
                'SIGNING_KEY': self.private_pem,
                'VERIFYING_KEY': self.public_pem,
            },
        ):
            auth = ShellUIJWTAuthentication()
            with self.assertRaises(InvalidToken):
                auth.get_validated_token(raw)


class IssAudValidationTests(SimpleTestCase):
    secret_key = 'unit-test-secret-key-not-for-production'
    issuer = 'https://auth.example.com'
    audience = 'shellui'
    jwt_settings = {
        'ALGORITHM': 'HS256',
        'SIGNING_KEY': secret_key,
        'VERIFYING_KEY': secret_key,
        'ISSUER': issuer,
        'AUDIENCE': audience,
    }

    def test_token_without_iss_aud_rejected_in_production_mode(self):
        backend = TokenBackend(
            algorithm='HS256',
            signing_key=self.secret_key,
            verifying_key=self.secret_key,
        )
        raw = backend.encode({'token_type': 'access', 'exp': 9999999999})

        with override_settings(
            SECRET_KEY=self.secret_key,
            JWT_ISSUER=self.issuer,
            JWT_AUDIENCE=self.audience,
            SIMPLE_JWT=self.jwt_settings,
        ):
            auth = ShellUIJWTAuthentication()
            with self.assertRaises(InvalidToken):
                auth.get_validated_token(raw)

    def test_token_with_wrong_audience_rejected(self):
        import jwt as pyjwt

        raw = pyjwt.encode(
            {
                'token_type': 'access',
                'exp': 9999999999,
                'aud': 'wrong',
                'iss': self.issuer,
            },
            self.secret_key,
            algorithm='HS256',
        )

        with override_settings(
            SECRET_KEY=self.secret_key,
            JWT_ISSUER=self.issuer,
            JWT_AUDIENCE=self.audience,
            SIMPLE_JWT=self.jwt_settings,
        ):
            auth = ShellUIJWTAuthentication()
            with self.assertRaises(InvalidToken):
                auth.get_validated_token(raw)


class ProductionChecksTests(SimpleTestCase):
    @override_settings(
        DEBUG=False,
        CORS_ALLOW_ALL_ORIGINS=False,
        JWT_ISSUER=None,
        JWT_AUDIENCE=None,
    )
    def test_missing_iss_aud_fails_check(self):
        errors = jwt_issuer_audience_required_in_production(None)
        self.assertTrue(errors)
        self.assertEqual(errors[0].id, 'authapi.E002')

    @override_settings(
        DEBUG=False,
        CORS_ALLOW_ALL_ORIGINS=True,
        JWT_ISSUER='https://auth.example.com',
        JWT_AUDIENCE='shellui',
    )
    def test_cors_allow_all_fails_in_production(self):
        errors = cors_allow_all_forbidden_in_production(None)
        self.assertTrue(errors)
        self.assertEqual(errors[0].id, 'authapi.E003')

    @override_settings(
        DEBUG=False,
        CORS_ALLOW_ALL_ORIGINS=False,
        JWT_ISSUER='https://auth.example.com',
        JWT_AUDIENCE='shellui',
        JWT_ACCEPT_HS256_LEGACY=True,
        JWKS_ENABLED=True,
    )
    def test_hs256_legacy_warns_in_production(self):
        warnings = jwt_hs256_legacy_disabled_in_production(None)
        self.assertTrue(warnings)
        self.assertEqual(warnings[0].id, 'authapi.W001')


@override_settings(
    CORS_ALLOW_ALL_ORIGINS=False,
    CORS_ALLOWED_ORIGINS=['https://allowed.example.com'],
    CORS_ALLOW_CREDENTIALS=False,
)
class ProductionCorsTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_preflight_rejects_unknown_origin(self):
        response = self.client.options(
            '/.well-known/jwks.json',
            HTTP_ORIGIN='https://vpzzsxvzsmp7.shellui.app',
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
            HTTP_ACCESS_CONTROL_REQUEST_HEADERS='authorization',
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Access-Control-Allow-Origin', response)

    def test_preflight_allows_configured_origin(self):
        origin = 'https://allowed.example.com'
        response = self.client.options(
            '/.well-known/jwks.json',
            HTTP_ORIGIN=origin,
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
            HTTP_ACCESS_CONTROL_REQUEST_HEADERS='authorization',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Access-Control-Allow-Origin'], origin)


@override_settings(CORS_ALLOW_ALL_ORIGINS=True, CORS_ALLOW_CREDENTIALS=False)
class PermissiveCorsTests(TestCase):
    """Development-style permissive CORS remains available when explicitly enabled."""

    def setUp(self):
        self.client = Client()

    def test_preflight_allows_random_hosting_preview_origin(self):
        origin = 'https://vpzzsxvzsmp7.shellui.app'
        response = self.client.options(
            '/.well-known/jwks.json',
            HTTP_ORIGIN=origin,
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
            HTTP_ACCESS_CONTROL_REQUEST_HEADERS='authorization',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Access-Control-Allow-Origin'], '*')
