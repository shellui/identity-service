"""``owner_user_id`` on agent access tokens, including JWKS verification."""

from __future__ import annotations

import uuid
from datetime import timedelta
from unittest import mock

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework_simplejwt.settings import APISettings, DEFAULTS, IMPORT_STRINGS

from apps.agents.models import Agent
from apps.agents.personal_agent_tokens import create_personal_agent_credential
from apps.agents.tokens import (
    build_agent_access_token,
    encode_access_token,
    issue_agent_refresh,
    refresh_agent_access,
)
from apps.authapi.jwks import build_jwks_document, generate_rsa_key_pair, load_signing_key
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

SETTINGS = dict(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AI_SERVICE_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
)


def _assert_owner(test, claims, user_id):
    test.assertIn('owner_user_id', claims)
    test.assertEqual(claims['owner_user_id'], user_id)
    test.assertIsInstance(claims['owner_user_id'], int)
    test.assertNotIsInstance(claims['owner_user_id'], bool)


@override_settings(**SETTINGS)
class AgentOwnerUserIdClaimTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-owner-claim')
        self.user = User.objects.create_user(username='ada', email='ada@acme.test', password='unused')
        set_company_access(self.company, self.user, enabled=True)
        self.resource = f'https://ai.test/c/{self.company.id}/mcp'

    def _owned_agent(self, **extra):
        defaults = dict(
            company=self.company,
            name='Owned',
            created_by=self.user,
            services_allowed=['ai', 'identity'],
            access_mode=Agent.ACCESS_ASK,
            read_level=Agent.READ_SAFE,
        )
        defaults.update(extra)
        return Agent.objects.create(**defaults)

    def test_access_token_includes_integer_owner_and_keeps_other_claims(self):
        agent = self._owned_agent()
        claims = build_agent_access_token(agent, resource=self.resource)
        _assert_owner(self, claims, self.user.pk)
        self.assertEqual(claims['aud'], self.resource)
        self.assertEqual(claims['scope'], 'ai identity')
        self.assertEqual(claims['agent_id'], str(agent.id))
        self.assertEqual(claims['sub'], f'agent:{agent.id}')
        self.assertNotIn('mcp_gateway_delegated', claims)

        delegated = build_agent_access_token(agent, resource=self.resource, gateway_delegated=True)
        _assert_owner(self, delegated, self.user.pk)
        self.assertTrue(delegated['mcp_gateway_delegated'])
        self.assertEqual(delegated['aud'], claims['aud'])
        self.assertEqual(delegated['scope'], claims['scope'])

    def test_omits_claim_when_agent_has_no_owner(self):
        service_agent = Agent.objects.create(
            company=self.company,
            name='Company service',
            services_allowed=['ai', 'identity'],
        )
        claims = build_agent_access_token(service_agent, resource=self.resource)
        self.assertNotIn('owner_user_id', claims)
        token = encode_access_token(service_agent, resource=self.resource)
        decoded = jwt.decode(token, options={'verify_signature': False})
        self.assertNotIn('owner_user_id', decoded)
        self.assertEqual(decoded['aud'], self.resource)
        self.assertEqual(decoded['scope'], 'ai identity')

        global_agent = Agent.objects.create(
            company=self.company,
            name='Global',
            global_agent_id=uuid.uuid4(),
            services_allowed=['ai'],
        )
        global_claims = build_agent_access_token(global_agent, resource=self.resource)
        self.assertNotIn('owner_user_id', global_claims)
        self.assertEqual(global_claims['mcp_authority'], 'delegated')

    def test_personal_token_includes_owner_user_id(self):
        _row, access = create_personal_agent_credential(
            user=self.user,
            company=self.company,
            name='My CLI',
            services=['identity', 'storage'],
            access_mode='read_only',
            read_level='safe',
            allow_destructive=False,
            expires_at=timezone.now() + timedelta(days=7),
        )
        claims = jwt.decode(access, options={'verify_signature': False})
        _assert_owner(self, claims, self.user.pk)
        self.assertEqual(claims['aud'], self.resource)
        self.assertIn('personal_token_id', claims)
        self.assertNotIn('mcp_authority', claims)

    def test_refresh_keeps_owner_user_id(self):
        agent = self._owned_agent()
        refresh, _session = issue_agent_refresh(agent, resource=self.resource)
        pair = refresh_agent_access(refresh, resource=self.resource)
        self.assertIsNotNone(pair)
        access, _new_refresh = pair
        claims = jwt.decode(access, options={'verify_signature': False})
        _assert_owner(self, claims, self.user.pk)
        self.assertEqual(claims['aud'], self.resource)
        self.assertEqual(claims['scope'], 'ai identity')

    def test_refresh_of_unowned_agent_still_omits_claim(self):
        agent = Agent.objects.create(
            company=self.company,
            name='Service',
            services_allowed=['ai', 'identity'],
        )
        refresh, _session = issue_agent_refresh(agent, resource=self.resource)
        pair = refresh_agent_access(refresh, resource=self.resource)
        self.assertIsNotNone(pair)
        access, _new_refresh = pair
        claims = jwt.decode(access, options={'verify_signature': False})
        self.assertNotIn('owner_user_id', claims)
        self.assertEqual(claims['aud'], self.resource)


@override_settings(**SETTINGS)
class AgentOwnerUserIdJwksTests(TestCase):
    def test_rs256_token_verifies_with_jwks_public_key(self):
        company = Company.objects.create(name='Jwks Co', slug='jwks-owner-claim')
        user = User.objects.create_user(username='jwks', email='jwks@acme.test', password='unused')
        set_company_access(company, user, enabled=True)
        agent = Agent.objects.create(
            company=company,
            name='Owned',
            created_by=user,
            services_allowed=['ai', 'identity'],
        )
        resource = f'https://ai.test/c/{company.id}/mcp'
        private, public = generate_rsa_key_pair(2048)
        signing = load_signing_key(private_pem=private, public_pem=public)
        jwks = build_jwks_document(signing)
        rs256 = APISettings(
            {
                'ALGORITHM': 'RS256',
                'SIGNING_KEY': private,
                'VERIFYING_KEY': public,
                'ISSUER': 'https://identity.test',
                'AUDIENCE': 'shellui-test',
            },
            DEFAULTS,
            IMPORT_STRINGS,
        )
        with (
            mock.patch('apps.agents.tokens.api_settings', rs256),
            override_settings(JWT_ACTIVE_KEY_ID=signing.kid, JWT_ISSUER='https://identity.test'),
        ):
            token = encode_access_token(agent, resource=resource)
        header = jwt.get_unverified_header(token)
        self.assertEqual(header['alg'], 'RS256')
        self.assertEqual(header['kid'], jwks['keys'][0]['kid'])
        payload = jwt.decode(
            token,
            public,
            algorithms=['RS256'],
            audience=resource,
            issuer='https://identity.test',
        )
        _assert_owner(self, payload, user.pk)
        self.assertEqual(payload['aud'], resource)
        self.assertEqual(payload['scope'], 'ai identity')
        self.assertEqual(payload['agent_id'], str(agent.id))
