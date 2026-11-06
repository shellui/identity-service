"""Dashboard global-company call logs. Regional ingest and the 15-key authority response stay put."""

from __future__ import annotations

import json
import time
import uuid

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.agents.call_log_global import select_sole_active
from apps.agents.models import Agent, GlobalAgentRevocation, McpCallLog
from apps.agents.tests.mcp_test_settings import (
    TEST_CALLER_SIGNING,
    TRUSTED_TEST_CALLER_SETTINGS,
)
from apps.authapi.jwks import build_jwks_document, generate_rsa_key_pair, load_signing_key
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.federation.models import ProvisionedCompany, UpstreamAccount
from shellui_django.mcp.internal import CALL_LOG_AUDIENCE, CALL_LOG_SCOPE, build_mcp_call_log_assertion

User = get_user_model()

_GLOBAL = 'https://global.id.example'
_DASH_ISS = 'https://dashboard.example'
_IDENTITY = 'https://identity.test'
_PATH = '/api/v1/mcp/internal/mcp-call-logs'

_REGIONAL_LOG_KEYS = {
    'id',
    'agent_id',
    'agent_name',
    'service',
    'tool',
    'operation_title',
    'access_kind',
    'outcome',
    'resource_label',
    'company_name',
    'approval_id',
    'method',
    'path',
    'status_code',
    'duration_ms',
    'arguments',
    'created_at',
}


def _dashboard_assertion(*, private_pem: str, kid: str, extra: dict) -> str:
    now = int(time.time())
    claims = {
        'iss': _DASH_ISS,
        'aud': CALL_LOG_AUDIENCE,
        'sub': 'service',
        'scope': CALL_LOG_SCOPE,
        'target': _IDENTITY,
        'iat': now,
        'exp': now + 55,
        'jti': uuid.uuid4().hex,
        **extra,
    }
    token = jwt.encode(claims, private_pem, algorithm='RS256', headers={'kid': kid})
    return token.decode('utf-8') if isinstance(token, bytes) else token


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER=_IDENTITY,
    JWT_AUDIENCE='shellui-test',
    GLOBAL_ISSUER_URL=_GLOBAL,
    PROVISIONING_ISSUER=_DASH_ISS,
    STORAGE_SERVICE_URL='https://storage.region.example',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class GlobalDashboardCallLogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        priv, pub = generate_rsa_key_pair(2048)
        cls._dash_key = load_signing_key(private_pem=priv, public_pem=pub)

    def setUp(self):
        self.company = Company.objects.create(name='Dash Co', slug='dash-co')
        self.owner = User.objects.create_user('own-dash', 'own-dash@example.com', 'x')
        self.company.owners.add(self.owner)
        self.company.members.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.gc = uuid.uuid4()
        self.ga = uuid.uuid4()
        ProvisionedCompany.objects.create(company=self.company, global_company_id=str(self.gc), limits_version=2)
        UpstreamAccount.objects.create(user=self.owner, issuer=_GLOBAL, sub='owner-sub-1', email=self.owner.email)

    def _settings(self):
        pem = self._dash_key.public_pem
        if isinstance(pem, bytes):
            pem = pem.decode('utf-8')
        return override_settings(PROVISIONING_PUBLIC_KEY=pem)

    def _claims(self, **overrides):
        base = {
            'agent_audit_scope': 'global_company',
            'global_agent_id': str(self.ga),
            'global_company_id': str(self.gc),
            'global_user_sub': 'owner-sub-1',
            'grant_version': 2,
            'company_binding_version': 2,
        }
        base.update(overrides)
        return base

    def _post(self, body: dict, *, claims: dict | None = None, path: str = _PATH):
        pem = self._dash_key.private_pem
        if isinstance(pem, bytes):
            pem = pem.decode('utf-8')
        token = _dashboard_assertion(private_pem=pem, kid=self._dash_key.kid, extra=claims if claims is not None else self._claims())
        return self.client.post(
            path,
            data=json.dumps(body),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )

    def _body(self, **overrides):
        body = {
            'service': 'storage',
            'tool': 'list_buckets',
            'method': 'POST',
            'path': '/mcp',
            'outcome': 'allowed',
            'access_kind': 'read',
            'status': 200,
            'duration_ms': 4,
        }
        body.update(overrides)
        return body

    def test_read_without_regional_agent_uses_provisioned_company(self):
        with self._settings():
            response = self._post(self._body())
        self.assertEqual(response.status_code, 201, response.content)
        log = McpCallLog.objects.get(pk=response.json()['id'])
        self.assertIsNone(log.agent_id)
        self.assertEqual(log.company_id, self.company.pk)
        self.assertEqual(log.global_agent_id, self.ga)
        self.assertEqual(log.global_company_id, self.gc)
        self.assertEqual(log.arguments_redacted, {})
        self.assertEqual(log.result, '')
        self.assertIsNone(log.client_ip)
        self.assertFalse(Agent.objects.filter(pk=self.ga).exists())
        self.assertFalse(Company.objects.filter(pk=0).exists())
        self.assertNotIn('arguments', response.json())

    def test_links_one_active_regional_agent_without_using_global_id_as_pk(self):
        regional = Agent.objects.create(
            company=self.company,
            name='Regional',
            created_by=self.owner,
            global_agent_id=self.ga,
            global_company_id=self.gc,
            company_binding_version=2,
            grant_version=2,
            services_allowed=['storage'],
        )
        with self._settings():
            response = self._post(self._body(agent_id=str(self.ga)))
        self.assertEqual(response.status_code, 201, response.content)
        log = McpCallLog.objects.get(pk=response.json()['id'])
        self.assertEqual(log.agent_id, regional.id)
        self.assertNotEqual(log.agent_id, self.ga)

    def test_version_mismatch_does_not_attach_agent(self):
        Agent.objects.create(
            company=self.company,
            name='Stale',
            created_by=self.owner,
            global_agent_id=self.ga,
            global_company_id=self.gc,
            company_binding_version=2,
            grant_version=9,
            services_allowed=['storage'],
        )
        with self._settings():
            response = self._post(self._body())
        self.assertEqual(response.status_code, 201, response.content)
        log = McpCallLog.objects.get(pk=response.json()['id'])
        self.assertIsNone(log.agent_id)

    def test_rejects_company_zero_regional_pk_and_sensitive_fields(self):
        other = Agent.objects.create(company=self.company, name='Other', created_by=self.owner)
        with self._settings():
            zero = self._post(self._body(company_id=0))
            regional_pk = self._post(self._body(agent_id=str(other.id)))
            args = self._post(self._body(arguments={'a': 1}))
            ip = self._post(self._body(client_ip='203.0.113.5'))
            email = self._post(self._body(email='owner@example.com'))
            query = self._post(self._body(query='select 1'))
            raw_body = self._post(self._body(body={'x': 1}))
            qs = self._post(self._body(), path=_PATH + '?x=1')
        self.assertEqual(zero.status_code, 400, zero.content)
        self.assertEqual(regional_pk.status_code, 400, regional_pk.content)
        self.assertEqual(args.status_code, 400, args.content)
        self.assertEqual(ip.status_code, 400, ip.content)
        self.assertEqual(email.status_code, 400, email.content)
        self.assertEqual(query.status_code, 400, query.content)
        self.assertEqual(raw_body.status_code, 400, raw_body.content)
        self.assertEqual(qs.status_code, 400, qs.content)
        self.assertEqual(McpCallLog.objects.count(), 0)
        self.assertEqual(other.call_logs.count(), 0)

    def test_non_dashboard_marker_and_partial_claims_rejected(self):
        storage = build_mcp_call_log_assertion(
            audience_url=_IDENTITY,
            private_key_pem=TEST_CALLER_SIGNING['private_key_pem'],
            kid=TEST_CALLER_SIGNING['kid'],
            issuer=TEST_CALLER_SIGNING['issuer'],
        )
        # Rebuild with the marker using the storage key directly.
        now = int(time.time())
        marked = {
            'iss': TEST_CALLER_SIGNING['issuer'],
            'aud': CALL_LOG_AUDIENCE,
            'sub': 'service',
            'scope': CALL_LOG_SCOPE,
            'target': _IDENTITY,
            'iat': now,
            'exp': now + 55,
            'jti': uuid.uuid4().hex,
            'agent_audit_scope': 'global_company',
        }
        pem = TEST_CALLER_SIGNING['private_key_pem']
        if isinstance(pem, bytes):
            pem = pem.decode('utf-8')
        bad = jwt.encode(marked, pem, algorithm='RS256', headers={'kid': TEST_CALLER_SIGNING['kid']})
        if isinstance(bad, bytes):
            bad = bad.decode('utf-8')
        denied = self.client.post(
            _PATH,
            data=json.dumps(self._body()),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {bad}',
        )
        self.assertEqual(denied.status_code, 403, denied.content)
        with self._settings():
            partial = self._post(self._body(), claims={'agent_audit_scope': 'global_company', 'global_agent_id': str(self.ga)})
        self.assertEqual(partial.status_code, 400, partial.content)
        self.assertTrue(storage)

    def test_owner_binding_and_revocation(self):
        with self._settings():
            stranger = self._post(self._body(), claims=self._claims(global_user_sub='stranger-sub'))
            self.assertEqual(stranger.status_code, 403, stranger.content)
            mismatch = self._post(self._body(), claims=self._claims(grant_version=0, company_binding_version=0))
            self.assertEqual(mismatch.status_code, 409, mismatch.content)
        GlobalAgentRevocation.objects.create(global_agent_id=self.ga)
        with self._settings():
            revoked = self._post(self._body())
        self.assertEqual(revoked.status_code, 403, revoked.content)

    def test_missing_provisioned_company_is_404(self):
        ProvisionedCompany.objects.all().delete()
        with self._settings():
            response = self._post(self._body())
        self.assertEqual(response.status_code, 404, response.content)
        self.assertEqual(McpCallLog.objects.count(), 0)
        self.assertFalse(Company.objects.filter(pk=0).exists())

    def test_owner_list_shows_global_row_only_for_that_company(self):
        from apps.authapi.views import _issue_shellui_tokens

        with self._settings():
            created = self._post(self._body())
        self.assertEqual(created.status_code, 201, created.content)
        token = _issue_shellui_tokens(self.owner, company=self.company)['access_token']
        listed = self.client.get('/api/v1/mcp/call-logs', HTTP_AUTHORIZATION=f'Bearer {token}')
        self.assertEqual(listed.status_code, 200, listed.content)
        row = listed.json()['call_logs'][0]
        self.assertIsNone(row['agent_id'])
        self.assertEqual(row['agent_audit_scope'], 'global_company')
        self.assertEqual(row['global_agent_id'], str(self.ga))
        self.assertEqual(row['global_company_id'], str(self.gc))
        self.assertEqual(row['arguments'], {})
        self.assertNotIn('client_ip', row)
        self.assertNotIn('email', row)

        other = Company.objects.create(name='Other Co', slug='other-co')
        other_user = User.objects.create_user('other-own', 'other@example.com', 'x')
        other.owners.add(other_user)
        other.members.add(other_user)
        set_company_access(other, other_user, enabled=True)
        other_token = _issue_shellui_tokens(other_user, company=other)['access_token']
        other_list = self.client.get('/api/v1/mcp/call-logs', HTTP_AUTHORIZATION=f'Bearer {other_token}')
        self.assertEqual(other_list.status_code, 200, other_list.content)
        self.assertEqual(other_list.json()['call_logs'], [])

    def test_regional_list_keys_unchanged(self):
        from apps.authapi.views import _issue_shellui_tokens

        regional = Agent.objects.create(
            company=self.company,
            name='Personal',
            created_by=self.owner,
            services_allowed=['storage'],
        )
        token = build_mcp_call_log_assertion(
            audience_url=_IDENTITY,
            private_key_pem=TEST_CALLER_SIGNING['private_key_pem'],
            kid=TEST_CALLER_SIGNING['kid'],
            issuer=TEST_CALLER_SIGNING['issuer'],
        )
        response = self.client.post(
            _PATH,
            data=json.dumps(
                {
                    'agent_id': str(regional.id),
                    'company_id': self.company.pk,
                    'grant_version': 0,
                    'service': 'storage',
                    'tool': 'list_buckets',
                    'method': 'POST',
                    'path': '/mcp',
                    'outcome': 'allowed',
                    'access_kind': 'read',
                    'status': 200,
                    'duration_ms': 1,
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 201, response.content)
        log = McpCallLog.objects.get(pk=response.json()['id'])
        self.assertIsNone(log.global_agent_id)
        owner_token = _issue_shellui_tokens(self.owner, company=self.company)['access_token']
        listed = self.client.get('/api/v1/mcp/call-logs', HTTP_AUTHORIZATION=f'Bearer {owner_token}')
        row = listed.json()['call_logs'][0]
        self.assertEqual(set(row.keys()), _REGIONAL_LOG_KEYS)
        self.assertEqual(row['agent_id'], str(regional.id))

    def test_select_sole_active_ambiguous(self):
        first = Agent(name='a', company=self.company)
        second = Agent(name='b', company=self.company)
        agent, choice = select_sole_active([first, second])
        self.assertIsNone(agent)
        self.assertEqual(choice, 'ambiguous')
        one, one_choice = select_sole_active([first])
        self.assertEqual(one, first)
        self.assertEqual(one_choice, 'one')
