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
from apps.agents.tokens import issue_agent_refresh, refresh_agent_access
from apps.companies.models import Company, CompanyMembership
from apps.federation.exchange import ACCESS_TOKEN_TYPE
from apps.federation.models import ProvisionedCompany, UpstreamAccount
from apps.federation.signing import unix_now
from apps.federation.tests.test_federation import ISSUER, REGION, _CryptoMixin, _rsa

User = get_user_model()
GLOBAL_AGENT_AUD = 'shellui-global-agents'


@override_settings(
    JWT_ISSUER=REGION,
    AUTH_RATE_LIMIT_ENABLED=False,
    MCP_DYNAMIC_CLIENT_REGISTRATION=True,
)
class AgentTokenExchangeTests(_CryptoMixin, TestCase):
    def setUp(self):
        cache.clear()
        self.ai_origin = 'https://ai.region.example'
        self._enable(
            SHELLUI_INSTANCE_ROLE='region',
            JWT_ISSUER=REGION,
            GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE=GLOBAL_AGENT_AUD,
            AI_SERVICE_URL=self.ai_origin,
            STORAGE_SERVICE_URL='https://storage.region.example',
        )
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme-agent-x')
        self.other_company = Company.objects.create(name='Other', slug='other-agent-x')
        self.global_agent_id = uuid.uuid4()
        self.saas_global_company_id = uuid.uuid4()
        ProvisionedCompany.objects.create(company=self.company, global_company_id=str(self.saas_global_company_id))

    @property
    def _gateway_mcp(self) -> str:
        return f'{self.ai_origin}/c/{self.company.pk}/mcp'

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
            'scope': 'identity storage ai',
            'mcp_access': 'ask',
            'mcp_read': 'safe',
            'mcp_destructive': False,
            'user_metadata': {'full_name': 'Ada Lovelace', 'is_staff': False},
        }
        claims.update(extra)
        if 'global_company_id' not in claims:
            claims['global_company_id'] = str(self.saas_global_company_id)
        if 'company_binding_version' not in claims:
            claims['company_binding_version'] = 1
        key = signing or self.signing
        token = jwt.encode(claims, key.private_pem, algorithm='RS256', headers={'kid': key.kid})
        return token.decode() if isinstance(token, bytes) else token

    def _post(self, token, *, company_id=None, **extra):
        body = {
            'grant_type': GRANT_TYPE,
            'subject_token': token,
            'subject_token_type': ACCESS_TOKEN_TYPE,
            'company_id': company_id if company_id is not None else self.company.pk,
            'resource': self._gateway_mcp,
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
        self.assertEqual(claims['company_name'], self.company.name)
        self.assertEqual(claims['aud'], self._gateway_mcp)
        self.assertFalse(claims.get('mcp_destructive'))
        agent = Agent.objects.get(company=self.company, global_agent_id=self.global_agent_id)
        self.assertEqual(str(agent.id), claims['agent_id'])
        self.assertEqual(agent.created_by_id, user.pk)
        self.assertEqual(agent.services_allowed, ['ai', 'identity', 'storage'])
        self.assertFalse(agent.allow_destructive_without_asking)

    def test_delegated_exchange_never_sets_destructive_without_asking(self):
        self._member()
        response = self._post(self._global_agent_token(mcp_destructive=True))
        self.assertEqual(response.status_code, 200, response.content)
        claims = jwt.decode(response.json()['access_token'], options={'verify_signature': False})
        self.assertFalse(claims.get('mcp_destructive'))
        agent = Agent.objects.get(company=self.company, global_agent_id=self.global_agent_id)
        self.assertFalse(agent.allow_destructive_without_asking)
        self.assertTrue(agent.global_max_destructive)

    def test_rejects_string_allow_destructive_on_exchange_body(self):
        self._member()
        base = {
            'grant_type': GRANT_TYPE,
            'subject_token': self._global_agent_token(),
            'subject_token_type': ACCESS_TOKEN_TYPE,
            'company_id': self.company.pk,
            'resource': self._gateway_mcp,
            'allow_destructive': 'false',
        }
        response = self.client.post(
            '/oauth/mcp/token',
            data=json.dumps(base),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_setup_context_stored_and_echoed_on_regional_access_token(self):
        user = self._member()
        now = unix_now()
        setup_exp = now + 240
        response = self._post(
            self._global_agent_token(
                setup_flow=True,
                setup_context_company_id=self.company.pk,
                setup_expires_at=setup_exp,
                mcp_session_ttl_seconds=600,
            ),
        )
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        claims = jwt.decode(body['access_token'], options={'verify_signature': False})
        self.assertEqual(claims.get('setup_context_company_id'), self.company.pk)
        self.assertEqual(claims.get('setup_expires_at'), setup_exp)
        self.assertTrue(claims.get('setup_flow'))
        self.assertTrue(claims.get('mcp_new_company_grant'))
        self.assertEqual(claims.get('mcp_session_ttl_seconds'), 600)
        agent = Agent.objects.get(company=self.company, global_agent_id=self.global_agent_id)
        self.assertEqual(agent.setup_company_id, self.company.pk)
        self.assertIsNotNone(agent.setup_context_expires_at)
        self.assertTrue(agent.setup_new_company_grant)
        self.assertEqual(agent.setup_mcp_session_ttl_seconds, 600)
        self.assertAlmostEqual(
            agent.setup_context_expires_at.timestamp(),
            float(setup_exp),
            delta=2,
        )

    def test_rejects_legacy_setup_context_exp_on_global_token(self):
        self._member()
        now = unix_now()
        setup_exp = now + 240
        response = self._post(
            self._global_agent_token(
                setup_flow=True,
                setup_context_company_id=self.company.pk,
                setup_context_exp=setup_exp,
                mcp_session_ttl_seconds=600,
            ),
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_global_company_binding_stored_at_exchange(self):
        self._member()
        gc = self.saas_global_company_id
        response = self._post(
            self._global_agent_token(global_company_id=str(gc), company_binding_version=3),
        )
        self.assertEqual(response.status_code, 200, response.content)
        claims = jwt.decode(response.json()['access_token'], options={'verify_signature': False})
        self.assertEqual(claims.get('global_company_id'), str(gc))
        self.assertEqual(claims.get('company_binding_version'), 3)
        agent = Agent.objects.get(company=self.company, global_agent_id=self.global_agent_id)
        self.assertEqual(agent.global_company_id, gc)
        self.assertEqual(agent.company_binding_version, 3)

    def test_mismatched_setup_context_company_rejected(self):
        self._member()
        now = unix_now()
        response = self._post(
            self._global_agent_token(
                setup_flow=True,
                setup_context_company_id=self.other_company.pk,
                setup_expires_at=now + 240,
                mcp_session_ttl_seconds=600,
            ),
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')

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
        self.assertEqual(response.json()['error'], 'invalid_target')
        self.assertFalse(Agent.objects.filter(company=self.other_company).exists())

    def test_staff_refused(self):
        self._member()
        for token in (
            self._global_agent_token(user_metadata={'is_staff': True}),
            self._global_agent_token(is_staff=True),
            self._global_agent_token(is_superuser=True),
        ):
            response = self._post(token)
            self.assertEqual(response.status_code, 400, token)
            self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_non_boolean_staff_metadata_refused(self):
        self._member()
        response = self._post(self._global_agent_token(user_metadata={'is_staff': 'false'}))
        self.assertEqual(response.status_code, 400)
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
            self._global_agent_token(scope='identity ai'),
            services='storage',
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_exchange_keeps_narrower_services_when_body_omitted(self):
        self._member()
        gc = str(self.saas_global_company_id)
        first = self._post(
            self._global_agent_token(
                scope='identity storage ai',
                global_company_id=gc,
                company_binding_version=1,
            )
        )
        self.assertEqual(first.status_code, 200)
        agent = Agent.objects.get(global_agent_id=self.global_agent_id)
        self.assertEqual(agent.services_allowed, ['ai', 'identity', 'storage'])
        second = self._post(
            self._global_agent_token(
                scope='identity storage hosting ai',
                global_company_id=gc,
                company_binding_version=1,
            )
        )
        self.assertEqual(second.status_code, 200)
        agent.refresh_from_db()
        self.assertEqual(agent.services_allowed, ['ai', 'identity', 'storage'])

    def test_omitted_services_empty_intersection_with_regional_refused(self):
        self._member()
        gc = str(self.saas_global_company_id)
        first = self._post(
            self._global_agent_token(
                scope='identity ai',
                global_company_id=gc,
                company_binding_version=1,
            ),
        )
        self.assertEqual(first.status_code, 200)
        # Force a regional row that no longer overlaps the next global cap (test-only).
        Agent.objects.filter(company=self.company, global_agent_id=self.global_agent_id).update(
            services_allowed=['identity']
        )
        second = self._post(
            self._global_agent_token(
                scope='storage ai',
                global_company_id=gc,
                company_binding_version=1,
            ),
        )
        self.assertEqual(second.status_code, 400)
        self.assertEqual(second.json()['error'], 'invalid_grant')

    def test_requested_services_intersects_with_existing_allowed(self):
        self._member()
        gc = str(self.saas_global_company_id)
        first = self._post(
            self._global_agent_token(
                scope='identity storage hosting ai',
                global_company_id=gc,
                company_binding_version=1,
            )
        )
        self.assertEqual(first.status_code, 200)
        second = self._post(
            self._global_agent_token(
                scope='identity storage email ai',
                global_company_id=gc,
                company_binding_version=1,
            ),
            services=['storage'],
        )
        self.assertEqual(second.status_code, 200)
        agent = Agent.objects.get(global_agent_id=self.global_agent_id)
        self.assertEqual(agent.services_allowed, ['storage'])

    def test_exchange_refuses_broadening_past_initial_global_cap(self):
        self._member()
        gc = str(self.saas_global_company_id)
        narrow = self._post(
            self._global_agent_token(
                scope='identity ai',
                mcp_access='read_only',
                global_company_id=gc,
                company_binding_version=1,
            ),
            access_mode='read_only',
        )
        self.assertEqual(narrow.status_code, 200)
        wide = self._post(
            self._global_agent_token(
                scope='identity ai',
                mcp_access='full',
                global_company_id=gc,
                company_binding_version=1,
            )
        )
        self.assertEqual(wide.status_code, 400)
        self.assertEqual(wide.json()['error'], 'invalid_grant')

    def test_requires_global_company_binding_pair(self):
        self._member()
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
            'scope': 'identity ai',
            'mcp_access': 'ask',
            'mcp_read': 'safe',
            'mcp_destructive': False,
            'user_metadata': {'full_name': 'Ada Lovelace', 'is_staff': False},
        }
        token = jwt.encode(claims, self.signing.private_pem, algorithm='RS256', headers={'kid': self.signing.kid})
        if isinstance(token, bytes):
            token = token.decode()
        self.assertEqual(self._post(token).status_code, 400)

    def test_rejects_direct_service_mcp_resource(self):
        self._member()
        bad = self.client.post(
            '/oauth/mcp/token',
            data=json.dumps(
                {
                    'grant_type': GRANT_TYPE,
                    'subject_token': self._global_agent_token(),
                    'subject_token_type': ACCESS_TOKEN_TYPE,
                    'company_id': self.company.pk,
                    'resource': 'https://storage.region.example/mcp',
                }
            ),
            content_type='application/json',
        )
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.json()['error'], 'invalid_target')

    def test_rejects_other_region_gateway_resource(self):
        self._member()
        other = f'https://ai.other-region.example/c/{self.company.pk}/mcp'
        bad = self.client.post(
            '/oauth/mcp/token',
            data=json.dumps(
                {
                    'grant_type': GRANT_TYPE,
                    'subject_token': self._global_agent_token(),
                    'subject_token_type': ACCESS_TOKEN_TYPE,
                    'company_id': self.company.pk,
                    'resource': other,
                }
            ),
            content_type='application/json',
        )
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.json()['error'], 'invalid_target')

    def test_refresh_invalidated_after_narrowing_exchange(self):
        self._member()
        gc = str(self.saas_global_company_id)
        first = self._post(
            self._global_agent_token(
                scope='identity storage ai',
                global_company_id=gc,
                company_binding_version=1,
            )
        )
        self.assertEqual(first.status_code, 200)
        refresh = first.json()['refresh_token']
        agent = Agent.objects.get(global_agent_id=self.global_agent_id)
        r1, _ = issue_agent_refresh(agent, resource=self._gateway_mcp)
        self.assertIsNotNone(refresh_agent_access(r1, resource=self._gateway_mcp))

        second = self._post(
            self._global_agent_token(
                scope='identity ai',
                global_company_id=gc,
                company_binding_version=1,
            )
        )
        self.assertEqual(second.status_code, 200)
        agent.refresh_from_db()
        self.assertEqual(agent.services_allowed, ['ai', 'identity'])
        self.assertIsNone(refresh_agent_access(refresh, resource=self._gateway_mcp))
        self.assertIsNone(refresh_agent_access(r1, resource=self._gateway_mcp))
