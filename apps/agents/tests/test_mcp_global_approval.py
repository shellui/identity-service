"""Global-scope MCP approval create (company_id=0) uses verified owner, not forwarded flags."""

from __future__ import annotations

import json
import time
import uuid

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.authapi.jwks import build_jwks_document, generate_rsa_key_pair, load_signing_key
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.federation.models import ProvisionedCompany, UpstreamAccount
from shellui_django.mcp.internal import APPROVAL_AUDIENCE, APPROVAL_SCOPE

User = get_user_model()

_GLOBAL = 'https://global.id.example'
_DASH_ISS = 'https://dashboard.example'
_IDENTITY = 'https://identity.test'


def _build_dashboard_approval_assertion(
    *,
    claims_extra: dict,
    private_pem: str,
    kid: str,
) -> str:
    now = int(time.time())
    base = {
        'iss': _DASH_ISS,
        'aud': APPROVAL_AUDIENCE,
        'sub': 'agent:%s' % claims_extra['global_agent_id'],
        'scope': APPROVAL_SCOPE,
        'target': _IDENTITY,
        'iat': now,
        'exp': now + 55,
        'jti': uuid.uuid4().hex,
        **claims_extra,
    }
    token = jwt.encode(base, private_pem, algorithm='RS256', headers={'kid': kid})
    return token.decode('utf-8') if isinstance(token, bytes) else token


@override_settings(
    JWT_ISSUER=_IDENTITY,
    JWT_AUDIENCE='shellui-test',
    GLOBAL_ISSUER_URL=_GLOBAL,
    PROVISIONING_ISSUER=_DASH_ISS,
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpGlobalApprovalCreateTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        priv, pub = generate_rsa_key_pair(2048)
        cls._dash_key = load_signing_key(private_pem=priv, public_pem=pub)
        cls._dash_jwks = build_jwks_document(cls._dash_key)

    def setUp(self):
        self.company = Company.objects.create(name='Gbl Co', slug='gbl-co')
        self.owner = User.objects.create_user('own', 'own@gbl.test', 'x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.gc = uuid.uuid4()
        ProvisionedCompany.objects.create(company=self.company, global_company_id=str(self.gc))
        UpstreamAccount.objects.create(user=self.owner, issuer=_GLOBAL, sub='owner-sub-1', email=self.owner.email)
        self.ga = uuid.uuid4()

    def _settings(self):
        return override_settings(
            PROVISIONING_PUBLIC_KEY=self._dash_key.public_pem.decode('utf-8')
            if isinstance(self._dash_key.public_pem, bytes)
            else self._dash_key.public_pem,
        )

    def _claims(self, **overrides):
        h = 'a' * 64
        base = {
            'company_id': 0,
            'agent_id': str(self.ga),
            'service': 'storage',
            'action': 'write_blob',
            'arguments_hash': h,
            'grant_version': 0,
            'global_company_id': str(self.gc),
            'company_binding_version': 0,
            'global_agent_id': str(self.ga),
            'global_user_sub': 'owner-sub-1',
        }
        base.update(overrides)
        return base

    def test_create_global_pending(self):
        with self._settings():
            assertion = _build_dashboard_approval_assertion(
                claims_extra=self._claims(),
                private_pem=self._dash_key.private_pem,
                kid=self._dash_key.kid,
            )
            r = self.client.post(
                '/api/v1/mcp/internal/mcp-approval-requests',
                data=json.dumps({}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {assertion}',
            )
        self.assertEqual(r.status_code, 200, r.content)
        from apps.agents.models import McpApprovalRequest

        row = McpApprovalRequest.objects.get(pk=r.json()['id'])
        self.assertIsNone(row.agent_id)
        self.assertIsNone(row.company_id)
        self.assertEqual(row.global_user_sub, 'owner-sub-1')

    def test_non_owner_sub_rejected(self):
        with self._settings():
            assertion = _build_dashboard_approval_assertion(
                claims_extra=self._claims(global_user_sub='stranger-sub'),
                private_pem=self._dash_key.private_pem,
                kid=self._dash_key.kid,
            )
            r = self.client.post(
                '/api/v1/mcp/internal/mcp-approval-requests',
                data=json.dumps({}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {assertion}',
            )
        self.assertEqual(r.status_code, 403, r.content)

    def test_state_finds_global_row(self):
        """State and consume routes must match global rows by global_agent_id, not agent_id."""
        claims = self._claims()
        with self._settings():
            assertion_create = _build_dashboard_approval_assertion(
                claims_extra=claims,
                private_pem=self._dash_key.private_pem,
                kid=self._dash_key.kid,
            )
            create_r = self.client.post(
                '/api/v1/mcp/internal/mcp-approval-requests',
                data=json.dumps({}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {assertion_create}',
            )
        self.assertEqual(create_r.status_code, 200, create_r.content)
        with self._settings():
            assertion_state = _build_dashboard_approval_assertion(
                claims_extra=claims,
                private_pem=self._dash_key.private_pem,
                kid=self._dash_key.kid,
            )
            state_r = self.client.post(
                '/api/v1/mcp/internal/mcp-approval-state',
                data=json.dumps({}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {assertion_state}',
            )
        self.assertEqual(state_r.status_code, 200, state_r.content)
        self.assertEqual(state_r.json()['status'], 'pending')
