"""Global MCP agent token exchange (RFC 8693) on regional Identity."""

from __future__ import annotations

import json
import uuid

import jwt
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.agents.exchange import GLOBAL_AGENT_TOKEN_TYPE, GRANT_TYPE
from apps.agents.models import Agent
from apps.companies.models import Company, CompanyMembership
from apps.federation.exchange import ACCESS_TOKEN_TYPE
from apps.federation.models import UpstreamAccount
from apps.federation.signing import unix_now
from apps.federation.tests.test_federation import ISSUER, REGION, _CryptoMixin, _rsa

User = get_user_model()
IDENTITY_MCP = 'https://region.example/mcp'
GLOBAL_AGENT_AUD = 'shellui-global-agents'


@override_settings(
    JWT_ISSUER=REGION,
    AUTH_RATE_LIMIT_ENABLED=False,
    MCP_DYNAMIC_CLIENT_REGISTRATION=True,
)
class AgentTokenExchangeTests(_CryptoMixin, TestCase):
    def setUp(self):
        cache.clear()
        self._enable(
            SHELLUI_INSTANCE_ROLE='region',
            JWT_ISSUER=REGION,
            GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE=GLOBAL_AGENT_AUD,
        )
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme-agent-x')
        self.other_company = Company.objects.create(name='Other', slug='other-agent-x')
        self.global_agent_id = uuid.uuid4()

    def _global_agent_token(self, signing=None, **extra):
        now = unix_now()
        claims = {
            'iss': ISSUER,
            'aud': GLOBAL_AGENT_AUD,
            'sub': '42',
            'agent_id': str(self.global_agent_id),
            'token_type': GLOBAL_AGENT_TOKEN_TYPE,
            'exp': now + 300,
            'iat': now,
            'jti': uuid.uuid4().hex,
            'email': 'ada@acme.test',
            'email_verified': True,
            'scope': 'identity storage',
            'mcp_access': 'ask',
            'mcp_read': 'safe',
            'mcp_destructive': False,
            'user_metadata': {'full_name': 'Ada Lovelace', 'is_staff': False},
        }
        claims.update(extra)
        key = signing or self.signing
        token = jwt.encode(claims, key.private_pem, algorithm='RS256', headers={'kid': key.kid})
        return token.decode() if isinstance(token, bytes) else token

    def _post(self, token, *, company_id=None, **extra):
        body = {
            'grant_type': GRANT_TYPE,
            'subject_token': token,
            'subject_token_type': ACCESS_TOKEN_TYPE,
            'company_id': company_id if company_id is not None else self.company.pk,
            'resource': IDENTITY_MCP,
        }
        body.update(extra)
        return self.client.post(
            '/oauth/mcp/token',
            data=json.dumps(body),
            content_type='application/json',
        )

    def _member(self, company=None):
        company = company or self.company
        user = User.objects.create_user('ada', 'ada@acme.test')
        UpstreamAccount.objects.create(user=user, issuer=ISSUER, sub='42', email='ada@acme.test')
        CompanyMembership.objects.create(company=company, user=user, is_enabled=True)
        return user

    def test_happy_path_issues_regional_agent_token(self):
        user = self._member()
        response = self._post(self._global_agent_token())
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertTrue(body['access_token'])
        self.assertTrue(body['refresh_token'])
        claims = jwt.decode(body['access_token'], options={'verify_signature': False})
        self.assertEqual(claims['company_id'], self.company.pk)
        self.assertEqual(claims['aud'], IDENTITY_MCP)
        agent = Agent.objects.get(company=self.company, global_agent_id=self.global_agent_id)
        self.assertEqual(str(agent.id), claims['agent_id'])
        self.assertEqual(agent.created_by_id, user.pk)
        self.assertEqual(agent.services_allowed, ['identity', 'storage'])

    def test_reuse_same_regional_agent_row(self):
        self._member()
        first = self._post(self._global_agent_token())
        self.assertEqual(first.status_code, 200)
        count = Agent.objects.filter(global_agent_id=self.global_agent_id).count()
        self.assertEqual(count, 1)
        second = self._post(self._global_agent_token())
        self.assertEqual(second.status_code, 200)
        self.assertEqual(Agent.objects.filter(global_agent_id=self.global_agent_id).count(), 1)

    def test_narrower_access_mode_allowed(self):
        self._member()
        response = self._post(
            self._global_agent_token(mcp_access='full'),
            access_mode='read_only',
        )
        self.assertEqual(response.status_code, 200)
        agent = Agent.objects.get(global_agent_id=self.global_agent_id)
        self.assertEqual(agent.access_mode, Agent.ACCESS_READ_ONLY)

    def test_broader_access_mode_refused(self):
        self._member()
        response = self._post(
            self._global_agent_token(mcp_access='read_only'),
            access_mode='full',
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_non_member_company_refused(self):
        self._member()
        response = self._post(self._global_agent_token(), company_id=self.other_company.pk)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')
        self.assertFalse(Agent.objects.filter(company=self.other_company).exists())

    def test_staff_refused(self):
        self._member()
        for token in (
            self._global_agent_token(user_metadata={'is_staff': True}),
            self._global_agent_token(is_staff=True),
            self._global_agent_token(user_metadata={'full_name': 'Ada'}),
        ):
            response = self._post(token)
            self.assertEqual(response.status_code, 400, token)
            self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_bad_global_tokens_refused(self):
        self._member()
        other, _ = _rsa()
        for token in (
            self._global_agent_token(iss='https://evil.example'),
            self._global_agent_token(aud='wrong-aud'),
            self._global_agent_token(exp=unix_now() - 60),
            self._global_agent_token(signing=other),
            self._global_agent_token(token_type='access', sid='s1'),
            self._global_agent_token(email_verified='true'),
            jwt.encode({'iss': ISSUER, 'sub': '42'}, 'secret', algorithm='HS256'),
        ):
            response = self._post(token)
            self.assertEqual(response.status_code, 400, token)
            self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_jti_replay_refused(self):
        self._member()
        jti = uuid.uuid4().hex
        token = self._global_agent_token(jti=jti)
        self.assertEqual(self._post(token).status_code, 200)
        replay = self._post(self._global_agent_token(jti=jti))
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.json()['error'], 'invalid_grant')

    def test_cross_tenant_isolation(self):
        self._member(self.company)
        response = self._post(self._global_agent_token())
        self.assertEqual(response.status_code, 200)
        token_a = response.json()['access_token']
        claims = jwt.decode(token_a, options={'verify_signature': False})
        self.assertEqual(claims['company_id'], self.company.pk)
        other = Agent.objects.create(
            company=self.other_company,
            name='other',
            services_allowed=['identity'],
        )
        other_token = jwt.encode(
            {**claims, 'company_id': self.other_company.pk, 'agent_id': str(other.id), 'sub': f'agent:{other.id}'},
            self.signing.private_pem,
            algorithm='RS256',
            headers={'kid': self.signing.kid},
        )
        if isinstance(other_token, bytes):
            other_token = other_token.decode()
        gateway = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {other_token}',
        )
        self.assertIn(gateway.status_code, {401, 403})

    def test_global_revoke_blocks_exchange(self):
        self._member()
        from apps.agents.global_revocation import revoke_regional_agents_for_global

        revoke_regional_agents_for_global(self.global_agent_id)
        response = self._post(self._global_agent_token())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_disabled_without_audience(self):
        self._member()
        with self.settings(GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE=''):
            self.assertEqual(self._post(self._global_agent_token()).status_code, 404)

    def test_service_not_in_global_scope_refused(self):
        self._member()
        response = self._post(
            self._global_agent_token(scope='identity'),
            services='storage',
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')
