"""User tokens and MCP agent tokens trust different global issuers.

User exchange (`POST /oauth/token`) verifies `GLOBAL_ISSUER_URL` and `GLOBAL_JWKS`.
Agent exchange (`POST /oauth/mcp/token`) verifies `GLOBAL_AGENT_ISSUER_URL` and
`GLOBAL_AGENT_JWKS`, falling back to the user issuer when those are empty.
"""

from __future__ import annotations

import copy
import json
import uuid
from dataclasses import replace

import jwt
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.models import EventLog
from apps.agents.exchange import (
    GLOBAL_AGENT_MCP_AUTHORITY,
    GLOBAL_AGENT_TOKEN_TYPE,
    agent_exchange_enabled,
    global_agent_trust,
)
from apps.agents.global_revocation import revoke_regional_agents_for_global
from apps.agents.models import Agent
from apps.authapi.models import RefreshTokenSession
from apps.companies.models import Company, CompanyMembership
from apps.federation.exchange import ACCESS_TOKEN_TYPE, GRANT_TYPE, exchange_enabled, handle_token_exchange
from apps.federation.models import UpstreamAccount
from apps.federation.signing import unix_now
from apps.federation.tests.test_federation import ISSUER, REGION, _CryptoMixin, _rsa

User = get_user_model()

AGENT_ISSUER = 'https://saas.example'
USER_AUD = 'shellui-global'
AGENT_AUD = 'shellui-global-agents'
SHELL = 'https://dashboard.example.com'
LOGIN_SUCCEEDED = 'identity.auth.login.succeeded'


@override_settings(
    JWT_ISSUER=REGION,
    AUTH_RATE_LIMIT_ENABLED=False,
    MCP_DYNAMIC_CLIENT_REGISTRATION=True,
)
class TwoIssuerTrustTests(_CryptoMixin, TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.agent_signing, cls.agent_jwks = _rsa()

    def setUp(self):
        cache.clear()
        self.ai_origin = 'https://ai.region.example'
        self._enable(
            SHELLUI_INSTANCE_ROLE='region',
            JWT_ISSUER=REGION,
            GLOBAL_ISSUER_URL=ISSUER,
            GLOBAL_JWKS=self.jwks,
            GLOBAL_ACCESS_TOKEN_AUDIENCE=USER_AUD,
            GLOBAL_AGENT_ISSUER_URL=AGENT_ISSUER,
            GLOBAL_AGENT_JWKS=self.agent_jwks,
            GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE=AGENT_AUD,
            OIDC_CORS_ALLOWED_ORIGINS=[SHELL],
            AI_SERVICE_URL=self.ai_origin,
            STORAGE_SERVICE_URL='https://storage.region.example',
        )
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme-two-issuer')
        self.global_agent_id = uuid.uuid4()
        self.saas_company_id = uuid.uuid4()

    @property
    def _gateway(self) -> str:
        return f'{self.ai_origin}/c/{self.company.pk}/mcp'

    def _sign(self, signing, claims):
        token = jwt.encode(claims, signing.private_pem, algorithm='RS256', headers={'kid': signing.kid})
        return token.decode() if isinstance(token, bytes) else token

    def _user_claims(self, **extra):
        now = unix_now()
        claims = {
            'iss': ISSUER,
            'aud': USER_AUD,
            'sub': '42',
            'exp': now + 300,
            'iat': now,
            'jti': uuid.uuid4().hex,
            'sid': 's1',
            'token_type': 'access',
            'email': 'ada@acme.test',
            'email_verified': True,
            'user_metadata': {'full_name': 'Ada Lovelace', 'is_staff': False},
        }
        claims.update(extra)
        return claims

    def _agent_claims(self, **extra):
        now = unix_now()
        claims = {
            'iss': AGENT_ISSUER,
            'aud': AGENT_AUD,
            'sub': '42',
            'agent_id': str(self.global_agent_id),
            'token_type': GLOBAL_AGENT_TOKEN_TYPE,
            'exp': now + 300,
            'iat': now,
            'jti': uuid.uuid4().hex,
            'email': 'ada@acme.test',
            'email_verified': True,
            'scope': 'identity storage ai',
            'mcp_access': 'ask',
            'mcp_read': 'safe',
            'mcp_destructive': False,
            'user_metadata': {'full_name': 'Ada Lovelace', 'is_staff': False},
            'mcp_authority': GLOBAL_AGENT_MCP_AUTHORITY,
            'global_company_id': str(self.saas_company_id),
            'company_binding_version': 1,
        }
        claims.update(extra)
        return claims

    def _user_token(self, signing=None, **extra):
        return self._sign(signing or self.signing, self._user_claims(**extra))

    def _agent_token(self, signing=None, **extra):
        return self._sign(signing or self.agent_signing, self._agent_claims(**extra))

    def _post_user(self, token, *, origin=SHELL):
        return self.client.post(
            '/oauth/token',
            {
                'grant_type': GRANT_TYPE,
                'subject_token': token,
                'subject_token_type': ACCESS_TOKEN_TYPE,
                'company_id': str(self.company.pk),
            },
            HTTP_ORIGIN=origin,
        )

    def _post_agent(self, token, **extra):
        body = {
            'grant_type': GRANT_TYPE,
            'subject_token': token,
            'subject_token_type': ACCESS_TOKEN_TYPE,
            'company_id': self.company.pk,
            'resource': self._gateway,
        }
        body.update(extra)
        return self.client.post('/oauth/mcp/token', data=json.dumps(body), content_type='application/json')

    def _user_exchange(self, token):
        request = RequestFactory().post('/oauth/token')
        request.data = {
            'grant_type': GRANT_TYPE,
            'subject_token': token,
            'subject_token_type': ACCESS_TOKEN_TYPE,
            'company_id': self.company.pk,
        }
        request.META['HTTP_ORIGIN'] = SHELL
        return handle_token_exchange(request)

    def _member(self):
        user = User.objects.create_user('ada', 'ada@acme.test')
        UpstreamAccount.objects.create(user=user, issuer=ISSUER, sub='42', email='ada@acme.test')
        CompanyMembership.objects.create(company=self.company, user=user, is_enabled=True)
        return user

    def test_user_token_from_user_issuer_accepted(self):
        user = self._member()
        response = self._post_user(self._user_token())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()['issued_token_type'], ACCESS_TOKEN_TYPE)
        self.assertTrue(RefreshTokenSession.objects.filter(user=user, company=self.company).exists())
        self.assertEqual(EventLog.objects.filter(event_type=LOGIN_SUCCEEDED, company=self.company).count(), 1)

    def test_agent_token_from_agent_issuer_accepted(self):
        user = self._member()
        before = EventLog.objects.filter(event_type=LOGIN_SUCCEEDED).count()
        response = self._post_agent(self._agent_token())
        self.assertEqual(response.status_code, 200, response.content)
        claims = jwt.decode(response.json()['access_token'], options={'verify_signature': False})
        self.assertEqual(claims.get('mcp_authority'), 'delegated')
        self.assertEqual(claims.get('aud'), self._gateway)
        agent = Agent.objects.get(company=self.company, global_agent_id=self.global_agent_id)
        self.assertEqual(agent.created_by_id, user.pk)
        self.assertEqual(agent.global_company_id, self.saas_company_id)
        self.assertEqual(agent.company_binding_version, 1)
        self.assertEqual(agent.grant_version, 0)
        self.assertEqual(UpstreamAccount.objects.filter(issuer=AGENT_ISSUER).count(), 0)
        self.assertEqual(UpstreamAccount.objects.filter(issuer=ISSUER, sub='42').count(), 1)
        self.assertEqual(EventLog.objects.filter(event_type=LOGIN_SUCCEEDED).count(), before)

    def test_each_token_rejected_at_the_other_endpoint(self):
        self._member()
        user_token = self._user_token()
        agent_token = self._agent_token()
        self.assertEqual(self._post_user(user_token).status_code, 200)
        self.assertEqual(self._post_agent(self._agent_token()).status_code, 200)

        at_agent = self._post_agent(user_token)
        self.assertEqual(at_agent.status_code, 400, at_agent.content)
        self.assertEqual(at_agent.json()['error'], 'invalid_grant')

        at_user = self._user_exchange(agent_token)
        self.assertEqual(at_user.status_code, 400, at_user.data)
        self.assertEqual(at_user.data['error'], 'invalid_grant')
        self.assertEqual(RefreshTokenSession.objects.count(), 1)

    def test_agent_shaped_token_on_oauth_token_uses_agent_issuer(self):
        """`POST /oauth/token` still dispatches agent-shaped tokens to agent exchange."""
        self._member()
        before = EventLog.objects.filter(event_type=LOGIN_SUCCEEDED).count()
        response = self.client.post(
            '/oauth/token',
            data=json.dumps(
                {
                    'grant_type': GRANT_TYPE,
                    'subject_token': self._agent_token(),
                    'subject_token_type': ACCESS_TOKEN_TYPE,
                    'company_id': self.company.pk,
                    'resource': self._gateway,
                }
            ),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200, response.content)
        claims = jwt.decode(response.json()['access_token'], options={'verify_signature': False})
        self.assertEqual(claims.get('mcp_authority'), 'delegated')
        self.assertEqual(EventLog.objects.filter(event_type=LOGIN_SUCCEEDED).count(), before)

    def test_iss_aud_and_kid_are_not_cross_accepted(self):
        self._member()
        user_key_agent_shape = self._sign(
            self.signing,
            self._agent_claims(iss=ISSUER, aud=AGENT_AUD),
        )
        agent_key_user_shape = self._sign(
            self.agent_signing,
            self._user_claims(iss=AGENT_ISSUER, aud=USER_AUD),
        )
        user_key_wrong_aud = self._user_token(aud=AGENT_AUD)
        agent_key_wrong_aud = self._agent_token(aud=USER_AUD)
        user_key_wrong_iss = self._sign(self.signing, self._agent_claims())
        agent_key_wrong_iss = self._sign(self.agent_signing, self._user_claims())

        for token in (
            user_key_agent_shape,
            user_key_wrong_iss,
            agent_key_wrong_aud,
        ):
            response = self._post_agent(token)
            self.assertEqual(response.status_code, 400, token)
            self.assertEqual(response.json()['error'], 'invalid_grant')

        for token in (
            agent_key_user_shape,
            agent_key_wrong_iss,
            user_key_wrong_aud,
        ):
            response = self._post_user(token)
            self.assertEqual(response.status_code, 400, token)
            self.assertEqual(response.json()['error'], 'invalid_grant')
            self.assertFalse(RefreshTokenSession.objects.exists())

    def test_key_from_the_other_jwks_rejected_even_with_the_same_kid(self):
        self._member()
        shared = 'shared-kid'
        user_jwks = copy.deepcopy(self.jwks)
        agent_jwks = copy.deepcopy(self.agent_jwks)
        user_jwks['keys'][0]['kid'] = shared
        agent_jwks['keys'][0]['kid'] = shared
        user_key = replace(self.signing, kid=shared)
        agent_key = replace(self.agent_signing, kid=shared)
        with self.settings(GLOBAL_JWKS=user_jwks, GLOBAL_AGENT_JWKS=agent_jwks):
            user_ok = self._post_user(self._user_token(signing=user_key))
            agent_ok = self._post_agent(self._agent_token(signing=agent_key))
            self.assertEqual(user_ok.status_code, 200, user_ok.content)
            self.assertEqual(agent_ok.status_code, 200, agent_ok.content)
            swapped = self._post_agent(self._sign(user_key, self._agent_claims()))
            self.assertEqual(swapped.status_code, 400, swapped.content)
            swapped_user = self._post_user(self._sign(agent_key, self._user_claims()))
            self.assertEqual(swapped_user.status_code, 400, swapped_user.content)

    def test_fallback_when_agent_settings_unset(self):
        self._member()
        with self.settings(GLOBAL_AGENT_ISSUER_URL='', GLOBAL_AGENT_JWKS={'keys': []}):
            issuer, document = global_agent_trust()
            self.assertEqual(issuer, ISSUER)
            self.assertEqual(document, self.jwks)
            self.assertTrue(agent_exchange_enabled())
            self.assertTrue(exchange_enabled())
            legacy = self._sign(self.signing, self._agent_claims(iss=ISSUER))
            response = self._post_agent(legacy)
            self.assertEqual(response.status_code, 200, response.content)
            user = self._post_user(self._user_token())
            self.assertEqual(user.status_code, 200, user.content)
            foreign = self._post_agent(self._agent_token())
            self.assertEqual(foreign.status_code, 400, foreign.content)
            self.assertEqual(foreign.json()['error'], 'invalid_grant')

    def test_issuer_and_jwks_fall_back_independently(self):
        with self.settings(GLOBAL_AGENT_ISSUER_URL=AGENT_ISSUER, GLOBAL_AGENT_JWKS={'keys': []}):
            issuer, document = global_agent_trust()
            self.assertEqual(issuer, AGENT_ISSUER)
            self.assertEqual(document, self.jwks)
        with self.settings(GLOBAL_AGENT_ISSUER_URL='', GLOBAL_AGENT_JWKS=self.agent_jwks):
            issuer, document = global_agent_trust()
            self.assertEqual(issuer, ISSUER)
            self.assertEqual(document, self.agent_jwks)

    def test_staff_refusal_intact(self):
        self._member()
        user_tokens = (
            self._user_token(user_metadata={'full_name': 'Ada', 'is_staff': True}),
            self._user_token(user_metadata={'full_name': 'Ada', 'is_staff': False, 'is_superuser': True}),
            self._user_token(is_superuser=True),
            self._user_token(user_metadata={'full_name': 'Ada'}),
        )
        for token in user_tokens:
            response = self._post_user(token)
            self.assertEqual(response.status_code, 400, token)
            body = response.json()
            self.assertEqual(body['error'], 'invalid_grant')
            self.assertIn('local account', body['error_description'])
        agent_tokens = (
            self._agent_token(user_metadata={'is_staff': True}),
            self._agent_token(is_staff=True),
            self._agent_token(is_superuser=True),
            self._agent_token(user_metadata={'is_staff': 'false'}),
        )
        for token in agent_tokens:
            response = self._post_agent(token)
            self.assertEqual(response.status_code, 400, token)
            body = response.json()
            self.assertEqual(body['error'], 'invalid_grant')
            self.assertIn('local account', body['error_description'])
        self.assertFalse(RefreshTokenSession.objects.exists())
        self.assertFalse(Agent.objects.exists())
        self.assertFalse(EventLog.objects.filter(event_type=LOGIN_SUCCEEDED).exists())

    def test_binding_downgrade_and_revocation_still_refused(self):
        self._member()
        first = self._post_agent(self._agent_token(company_binding_version=2))
        self.assertEqual(first.status_code, 200, first.content)
        agent = Agent.objects.get(global_agent_id=self.global_agent_id)
        self.assertEqual(agent.company_binding_version, 2)
        stale = self._post_agent(self._agent_token(company_binding_version=1))
        self.assertEqual(stale.status_code, 400, stale.content)
        self.assertEqual(stale.json()['error'], 'invalid_grant')
        self.assertIn('stale', stale.json()['error_description'])
        revoke_regional_agents_for_global(self.global_agent_id)
        blocked = self._post_agent(self._agent_token(company_binding_version=2))
        self.assertEqual(blocked.status_code, 400, blocked.content)
        self.assertEqual(blocked.json()['error'], 'invalid_grant')

    def test_narrowing_still_bumps_grant_version(self):
        self._member()
        first = self._post_agent(self._agent_token())
        self.assertEqual(first.status_code, 200, first.content)
        before = Agent.objects.get(global_agent_id=self.global_agent_id).grant_version
        second = self._post_agent(self._agent_token(), services=['identity'])
        self.assertEqual(second.status_code, 200, second.content)
        agent = Agent.objects.get(global_agent_id=self.global_agent_id)
        self.assertEqual(agent.services_allowed, ['identity'])
        self.assertGreater(agent.grant_version, before)
