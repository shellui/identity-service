"""Agent JWTs must verify with the public key under RS256 (regression: private key was used)."""

from __future__ import annotations

import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from unittest import mock

from django.test import SimpleTestCase, override_settings
from rest_framework_simplejwt.settings import APISettings, DEFAULTS, IMPORT_STRINGS

from apps.authapi.authentication import ShellUIJWTAuthentication


def _pems():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private, public


class AgentJwtRs256Tests(SimpleTestCase):
    def setUp(self):
        self.private, self.public = _pems()
        self.override = override_settings(
            JWT_ISSUER='http://issuer.test',
            SIMPLE_JWT={
                'ALGORITHM': 'RS256',
                'SIGNING_KEY': self.private,
                'VERIFYING_KEY': self.public,
                'ISSUER': 'http://issuer.test',
                'AUDIENCE': 'shellui',
            },
        )
        self.override.enable()
        self.addCleanup(self.override.disable)
        rs256 = APISettings(
            {'ALGORITHM': 'RS256', 'SIGNING_KEY': self.private, 'VERIFYING_KEY': self.public},
            DEFAULTS,
            IMPORT_STRINGS,
        )
        patcher = mock.patch('apps.authapi.authentication.api_settings', rs256)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _token(self, private, **extra):
        payload = {
            'sub': 'agent:1',
            'agent_id': 1,
            'aud': 'shellui',
            'iss': 'http://issuer.test',
            'exp': int(time.time()) + 60,
            **extra,
        }
        return jwt.encode(payload, private, algorithm='RS256')

    def test_valid_agent_token_verifies_with_public_key(self):
        payload = ShellUIJWTAuthentication()._decode_agent_jwt(self._token(self.private))
        self.assertEqual(payload['agent_id'], 1)

    def test_token_signed_by_another_key_is_rejected(self):
        other_private, _ = _pems()
        self.assertIsNone(ShellUIJWTAuthentication()._decode_agent_jwt(self._token(other_private)))

    def test_non_agent_subject_is_ignored(self):
        self.assertIsNone(ShellUIJWTAuthentication()._decode_agent_jwt(self._token(self.private, sub='42')))
