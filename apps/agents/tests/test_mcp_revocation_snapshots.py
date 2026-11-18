"""Revocation poll body matches the signed assertion, including active agent rows."""

from __future__ import annotations

import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from shellui_django.mcp.internal import build_mcp_revocation_assertion

from apps.agents.models import Agent
from apps.agents.tests.mcp_test_settings import (
    TEST_CALLER_SIGNING,
    TRUSTED_TEST_CALLER_SETTINGS,
    rs256_identity_settings,
)
from apps.agents.trusted_revocation import parse_trusted_revocation_poll_response_identity
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
