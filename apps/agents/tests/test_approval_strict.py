"""Strict JSON parsing for approval authority and assertion binding claims."""

from __future__ import annotations

import uuid
from unittest.mock import Mock

from django.test import SimpleTestCase

from apps.agents.approval_authority import agent_matches_approval_authority, parse_approval_authority_claims
from apps.agents.approval_internal import approval_binding_from_claims


class ParseApprovalAuthorityClaimsTests(SimpleTestCase):
    def test_rejects_bool_grant_version(self):
        parsed, err = parse_approval_authority_claims({'grant_version': True})
        self.assertIsNone(parsed)
        self.assertIsNotNone(err)

    def test_rejects_string_zero_grant_version(self):
        parsed, err = parse_approval_authority_claims({'grant_version': '0'})
        self.assertIsNone(parsed)

    def test_accepts_int_zero_grant_version(self):
        parsed, err = parse_approval_authority_claims({'grant_version': 0})
        self.assertIsNone(err)
        assert parsed is not None
        self.assertEqual(parsed['grant_version'], 0)

    def test_global_triplet_requires_both_binding_fields(self):
        gc = str(uuid.uuid4())
        parsed, err = parse_approval_authority_claims(
            {'grant_version': 0, 'global_company_id': gc, 'company_binding_version': None}
        )
        self.assertIsNone(parsed)
        self.assertIsNotNone(err)

    def test_personal_rejects_orphan_binding_version(self):
        parsed, err = parse_approval_authority_claims({'grant_version': 0, 'company_binding_version': 1})
        self.assertIsNone(parsed)

    def test_personal_rejects_global_without_binding(self):
        gc = str(uuid.uuid4())
        parsed, err = parse_approval_authority_claims({'grant_version': 0, 'global_company_id': gc})
        self.assertIsNone(parsed)


class ApprovalBindingFromClaimsTests(SimpleTestCase):
    def _base_claims(self, **overrides):
        base = {
            'agent_id': str(uuid.uuid4()),
            'company_id': 42,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'a' * 64,
        }
        base.update(overrides)
        return base

    def test_company_id_must_be_json_int(self):
        self.assertIsNone(approval_binding_from_claims(self._base_claims(company_id=True)))
        self.assertIsNone(approval_binding_from_claims(self._base_claims(company_id='0')))
        self.assertIsNone(approval_binding_from_claims(self._base_claims(company_id=1.0)))
        self.assertIsNotNone(approval_binding_from_claims(self._base_claims(company_id=42)))


class AgentMatchesApprovalAuthorityTests(SimpleTestCase):
    def _agent(self, **kwargs):
        defaults = {'grant_version': 1, 'global_company_id': None, 'company_binding_version': None}
        defaults.update(kwargs)
        return Mock(**defaults)

    def test_delegated_requires_both_binding_versions(self):
        gc = uuid.uuid4()
        auth = {'grant_version': 1, 'global_company_id': gc, 'company_binding_version': 2}
        agent = self._agent(
            grant_version=1,
            global_company_id=gc,
            company_binding_version=None,
        )
        self.assertFalse(agent_matches_approval_authority(agent, auth))
