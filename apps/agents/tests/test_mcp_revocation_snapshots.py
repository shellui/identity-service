"""Revocation poll body matches the signed assertion, including active agent rows."""

from __future__ import annotations

import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from shellui_django.mcp.internal import build_mcp_revocation_assertion

from apps.agents.models import Agent, DeletedAgentRevocation
from apps.agents.tests.mcp_test_settings import (
    TEST_CALLER_SIGNING,
    TRUSTED_TEST_CALLER_SETTINGS,
    rs256_identity_settings,
)
from apps.agents.trusted_revocation import parse_trusted_revocation_poll_response_identity
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()
_PATH = '/api/v1/mcp/internal/mcp-revocations'
_ORIGIN = 'https://identity.test'

_SNAPSHOT_KEYS = frozenset(
    {
        'agent_id',
        'company_id',
        'is_active',
        'paused',
        'grant_version',
        'global_company_id',
        'company_binding_version',
    }
)


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER=_ORIGIN,
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpRevocationSnapshotTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Rev Co', slug='rev-co')
        self.owner = User.objects.create_user('rev-own', 'rev@example.com', 'x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)

    def _get(self, *, company_id: int | None = None):
        assertion = build_mcp_revocation_assertion(audience_url=_ORIGIN, **TEST_CALLER_SIGNING)
        path = _PATH if company_id is None else f'{_PATH}?company_id={company_id}'
        return self.client.get(path, HTTP_AUTHORIZATION=f'Bearer {assertion}')

    def test_max_grant_parity_zero_and_positive(self):
        with rs256_identity_settings() as (_signing, jwks):
            empty = self._get()
            self.assertEqual(empty.status_code, 200, empty.content)
            body = empty.json()
            self.assertEqual(body['max_active_grant_version'], 0)
            self.assertEqual(body['cache_seconds'], 30)
            self.assertEqual(empty['Cache-Control'], 'private, max-age=30')
            _ids, cache, agents, _policy = parse_trusted_revocation_poll_response_identity(
                body, expected_issuer=_ORIGIN, jwks=jwks
            )
            self.assertEqual(cache, 30)
            self.assertEqual(agents, [])
            stripped = dict(body)
            stripped.pop('max_active_grant_version')
            with self.assertRaises(ValueError) as raised:
                parse_trusted_revocation_poll_response_identity(stripped, expected_issuer=_ORIGIN, jwks=jwks)
            self.assertEqual(str(raised.exception), 'Revocation list body mismatch')

            Agent.objects.create(
                company=self.company,
                name='Live',
                created_by=self.owner,
                grant_version=7,
                services_allowed=['storage'],
            )
            Agent.objects.create(
                company=self.company,
                name='Old',
                created_by=self.owner,
                grant_version=99,
                revoked_at=timezone.now(),
                services_allowed=['storage'],
            )
            positive = self._get(company_id=self.company.pk)
            self.assertEqual(positive.status_code, 200, positive.content)
            pdata = positive.json()
            self.assertEqual(pdata['max_active_grant_version'], 7)
            parse_trusted_revocation_poll_response_identity(pdata, expected_issuer=_ORIGIN, jwks=jwks)

    def test_active_agent_snapshot_and_optional_binding(self):
        global_company = uuid.uuid4()
        global_agent = uuid.uuid4()
        active = Agent.objects.create(
            company=self.company,
            name='Active',
            created_by=self.owner,
            grant_version=3,
            global_agent_id=global_agent,
            global_company_id=global_company,
            services_allowed=['storage'],
        )
        plain = Agent.objects.create(
            company=self.company,
            name='Plain',
            created_by=self.owner,
            grant_version=1,
            services_allowed=['storage'],
        )
        with rs256_identity_settings() as (_signing, jwks):
            response = self._get(company_id=self.company.pk)
            self.assertEqual(response.status_code, 200, response.content)
            data = response.json()
        by_id = {row['agent_id']: row for row in data['agents']}
        self.assertIn(str(active.id), by_id)
        self.assertNotIn(str(global_agent), by_id)
        row = by_id[str(active.id)]
        self.assertTrue(row['is_active'])
        self.assertFalse(row['paused'])
        self.assertEqual(row['grant_version'], 3)
        self.assertEqual(row['company_id'], self.company.pk)
        self.assertEqual(row['global_company_id'], str(global_company))
        self.assertNotIn('company_binding_version', row)
        self.assertNotIn('global_agent_id', row)
        self.assertNotIn('email', row)
        self.assertNotIn('name', row)
        self.assertTrue(set(row.keys()) <= _SNAPSHOT_KEYS)
        plain_row = by_id[str(plain.id)]
        self.assertTrue(plain_row['is_active'])
        self.assertNotIn('global_company_id', plain_row)
        self.assertNotIn('company_binding_version', plain_row)
        self.assertEqual(data['revoked_agent_ids'], [])
        parse_trusted_revocation_poll_response_identity(data, expected_issuer=_ORIGIN, jwks=jwks)

    def test_company_filter_and_policy_fingerprint(self):
        other = Company.objects.create(name='Other', slug='rev-other')
        here = Agent.objects.create(
            company=self.company,
            name='Here',
            created_by=self.owner,
            grant_version=2,
            services_allowed=['storage'],
        )
        elsewhere = Agent.objects.create(
            company=other,
            name='There',
            created_by=self.owner,
            grant_version=8,
            services_allowed=['storage'],
        )
        with rs256_identity_settings() as (_signing, jwks):
            first = self._get(company_id=self.company.pk)
            self.assertEqual(first.status_code, 200, first.content)
            data = first.json()
            ids = {row['agent_id'] for row in data['agents']}
            self.assertEqual(ids, {str(here.id)})
            self.assertNotIn(str(elsewhere.id), data['revoked_agent_ids'])
            self.assertEqual(data['max_active_grant_version'], 2)
            _a, _b, _c, policy_before = parse_trusted_revocation_poll_response_identity(
                data, expected_issuer=_ORIGIN, jwks=jwks
            )
            here.grant_version = 4
            here.global_company_id = uuid.uuid4()
            here.company_binding_version = 1
            here.save(update_fields=['grant_version', 'global_company_id', 'company_binding_version'])
            second = self._get(company_id=self.company.pk)
            data2 = second.json()
            self.assertEqual(data2['max_active_grant_version'], 4)
            bound = data2['agents'][0]
            self.assertEqual(bound['global_company_id'], str(here.global_company_id))
            self.assertEqual(bound['company_binding_version'], 1)
            self.assertTrue(bound['is_active'])
            _a, _b, _c, policy_after = parse_trusted_revocation_poll_response_identity(
                data2, expected_issuer=_ORIGIN, jwks=jwks
            )
            self.assertNotEqual(policy_before, policy_after)


def _storage_agent_blocked_for_tenant(agent_id, *, company_id, payload):
    """Copy of apps/storage/mcp_identity.py ``_agent_blocked_for_tenant`` (storage #90)."""
    revoked_ids = {str(item) for item in (payload.get('revoked_ids') or [])}
    if str(agent_id) not in revoked_ids:
        return False
    if company_id is None:
        return True
    agents = payload.get('agents') or []
    if not agents:
        return True
    for entry in agents:
        if str(entry.get('agent_id') or '') != str(agent_id):
            continue
        entry_company = entry.get('company_id')
        if entry_company is None:
            return True
        try:
            return int(entry_company) == int(company_id)
        except (TypeError, ValueError):
            return False
    return False


def _ai_agent_blocked_for_tenant(agent_id, *, company_id, payload):
    """Copy of apps/connector/mcp_identity.py ``_agent_blocked_for_tenant`` (ai #88)."""
    revoked_ids = {str(item) for item in (payload.get('revoked_ids') or [])}
    if str(agent_id) not in revoked_ids:
        return False
    if company_id is None:
        return True
    agents = payload.get('agents') or []
    if not agents:
        return True
    for entry in agents:
        if str(entry.get('agent_id') or '') != str(agent_id):
            continue
        entry_company = entry.get('company_id')
        if entry_company is None:
            return True
        raw = entry_company
        if isinstance(raw, bool) or raw is None:
            return True
        try:
            parsed = int(str(raw).strip()) if not isinstance(raw, int) else raw
        except ValueError:
            return True
        if parsed < 0:
            return True
        return parsed == int(company_id)
    return False


@override_settings(
    **TRUSTED_TEST_CALLER_SETTINGS,
    JWT_ISSUER=_ORIGIN,
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class DeletedAgentsAreRefusedByCompanyScopedConsumersTests(TestCase):
    """The real snapshot after a company delete, run through the ai and storage checks."""

    CHECKS = (_storage_agent_blocked_for_tenant, _ai_agent_blocked_for_tenant)

    def setUp(self):
        self.company = Company.objects.create(name='Gone Co', slug='gone-co-snap')
        self.other = Company.objects.create(name='Stay Co', slug='stay-co-snap')
        self.user = User.objects.create_user('gone-own', 'gone@example.com', 'x')
        for company in (self.company, self.other):
            company.owners.add(self.user)
            set_company_access(company, self.user, enabled=True)
        self.gone = Agent.objects.create(company=self.company, name='Gone', created_by=self.user, services_allowed=['ai'])
        self.live = Agent.objects.create(company=self.other, name='Live', created_by=self.user, services_allowed=['ai'])
        self.gone_id = str(self.gone.pk)
        self.gone_company_id = self.company.pk
        self.company.delete()

    def _poll(self, *, company_id=None):
        assertion = build_mcp_revocation_assertion(audience_url=_ORIGIN, **TEST_CALLER_SIGNING)
        path = _PATH if company_id is None else f'{_PATH}?company_id={company_id}'
        with rs256_identity_settings() as (_signing, jwks):
            response = self.client.get(path, HTTP_AUTHORIZATION=f'Bearer {assertion}')
            self.assertEqual(response.status_code, 200, response.content)
            body = response.json()
            ids, _cache, agents, _policy = parse_trusted_revocation_poll_response_identity(
                body, expected_issuer=_ORIGIN, jwks=jwks
            )
        return body, {'revoked_ids': sorted(ids), 'agents': agents}

    def test_a_company_scoped_check_refuses_the_deleted_agent(self):
        for company_id in (None, self.gone_company_id):
            body, payload = self._poll(company_id=company_id)
            self.assertIn(self.gone_id, payload['revoked_ids'])
            for check in self.CHECKS:
                with self.subTest(check=check.__name__, poll_company=company_id):
                    self.assertTrue(check(self.gone_id, company_id=self.gone_company_id, payload=payload))
                    self.assertTrue(check(self.gone_id, company_id=None, payload=payload))

    def test_the_tombstone_row_is_in_the_signed_agents_and_the_policy_version(self):
        _body, payload = self._poll()
        rows = [r for r in payload['agents'] if r['agent_id'] == self.gone_id]
        self.assertEqual(
            rows,
            [{'agent_id': self.gone_id, 'company_id': self.gone_company_id, 'is_active': False, 'paused': False, 'grant_version': 0}],
        )
        before = self._poll()[0]['revocation_policy_version']
        DeletedAgentRevocation.objects.filter(pk=self.gone_id).delete()
        after = self._poll()[0]['revocation_policy_version']
        self.assertNotEqual(before, after)

    def test_without_the_row_the_company_scoped_check_would_let_it_through(self):
        _body, payload = self._poll()
        stripped = {**payload, 'agents': [r for r in payload['agents'] if r['agent_id'] != self.gone_id]}
        self.assertTrue(stripped['agents'])
        for check in self.CHECKS:
            with self.subTest(check=check.__name__):
                self.assertFalse(check(self.gone_id, company_id=self.gone_company_id, payload=stripped))

    def test_the_deleted_agent_is_not_refused_for_another_company(self):
        _body, payload = self._poll()
        for check in self.CHECKS:
            with self.subTest(check=check.__name__):
                self.assertFalse(check(self.gone_id, company_id=self.other.pk, payload=payload))

    def test_a_live_agent_is_not_refused(self):
        _body, payload = self._poll()
        for check in self.CHECKS:
            with self.subTest(check=check.__name__):
                self.assertFalse(check(str(self.live.pk), company_id=self.other.pk, payload=payload))
