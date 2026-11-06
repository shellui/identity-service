"""Live HTTP smoke test for dashboard global call log ingest (no regional Agent row)."""

from __future__ import annotations

import json
import time
import uuid

import jwt
import requests
from django.contrib.auth import get_user_model
from django.test import LiveServerTestCase, override_settings

from apps.authapi.jwks import generate_rsa_key_pair, load_signing_key
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.federation.models import ProvisionedCompany, UpstreamAccount
from shellui_django.mcp.internal import CALL_LOG_AUDIENCE, CALL_LOG_SCOPE

User = get_user_model()

_GLOBAL = 'https://global.id.example'
_DASH_ISS = 'https://dashboard.example'
_IDENTITY = 'https://identity.test'


def _build_dashboard_call_log_assertion(*, private_pem: str, kid: str) -> str:
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
    }
    token = jwt.encode(claims, private_pem, algorithm='RS256', headers={'kid': kid})
    return token.decode('utf-8') if isinstance(token, bytes) else token


@override_settings(
    ALLOWED_HOSTS=['*'],
    JWT_ISSUER=_IDENTITY,
    JWT_AUDIENCE='shellui-test',
    GLOBAL_ISSUER_URL=_GLOBAL,
    PROVISIONING_ISSUER=_DASH_ISS,
    AUTH_RATE_LIMIT_ENABLED=False,
    STORAGE_SERVICE_URL='https://storage.region.example',
)
class McpGlobalCallLogLiveHttpTests(LiveServerTestCase):
    """Hits the real devserver port from LiveServerTestCase (TCP HTTP)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        priv, pub = generate_rsa_key_pair(2048)
        cls._dash_key = load_signing_key(private_pem=priv, public_pem=pub)

    def setUp(self):
        self.provisioning_key = (
            self._dash_key.public_pem.decode('utf-8')
            if isinstance(self._dash_key.public_pem, bytes)
            else self._dash_key.public_pem
        )
        with override_settings(PROVISIONING_PUBLIC_KEY=self.provisioning_key):
            self._setup_data()

    def _setup_data(self):
        self.company = Company.objects.create(name='HTTP Gbl', slug='http-gbl')
        self.owner = User.objects.create_user('httpown', 'httpown@gbl.test', 'x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.gc = uuid.uuid4()
        ProvisionedCompany.objects.create(company=self.company, global_company_id=str(self.gc), limits_version=1)
        UpstreamAccount.objects.create(user=self.owner, issuer=_GLOBAL, sub='http-owner-sub', email=self.owner.email)
        self.ga = uuid.uuid4()

    def test_post_global_call_log_returns_201_over_http(self):
        assertion = _build_dashboard_call_log_assertion(
            private_pem=self._dash_key.private_pem,
            kid=self._dash_key.kid,
        )
        url = f'{self.live_server_url}/api/v1/mcp/internal/mcp-call-logs'
        body = {
            'company_id': self.company.pk,
            'global_agent_id': str(self.ga),
            'global_company_id': str(self.gc),
            'grant_version': 1,
            'company_binding_version': 1,
            'service': 'storage',
            'tool': 'smoke_tool',
            'method': 'POST',
            'path': '/mcp',
            'status': 200,
            'duration_ms': 3,
            'outcome': 'allowed',
        }
        with override_settings(PROVISIONING_PUBLIC_KEY=self.provisioning_key):
            r = requests.post(
                url,
                data=json.dumps(body),
                headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {assertion}'},
                timeout=30,
            )
        self.assertEqual(r.status_code, 201, r.text)
        data = r.json()
        self.assertIn('id', data)
        from apps.agents.models import McpCallLog

        log = McpCallLog.objects.get(pk=data['id'])
        self.assertIsNone(log.agent_id)
        self.assertEqual(log.company_id, self.company.pk)
