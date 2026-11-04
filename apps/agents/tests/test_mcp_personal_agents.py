"""Personal MCP agent tokens for company members."""

from __future__ import annotations

import json
from datetime import timedelta

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.agents.models import Agent, McpCallLog, PersonalAgentCredential
from apps.agents.personal_agent_tokens import encode_personal_agent_access_token
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

SETTINGS = dict(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AI_SERVICE_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
)


@override_settings(**SETTINGS)
class PersonalAgentTokenTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-personal')
        self.other = Company.objects.create(name='Other', slug='other-personal')
        self.user = User.objects.create_user(username='mem', email='mem@acme.com', password='unused')
        set_company_access(self.company, self.user, enabled=True)
        self.resource = f'https://ai.test/c/{self.company.id}/mcp'

    def _member_token(self):
        from apps.authapi.views import _issue_shellui_tokens

        return _issue_shellui_tokens(self.user, company=self.company)['access_token']

    def test_status_and_create_list_revoke_activity(self):
        token = self._member_token()
        status = self.client.get(
            '/api/v1/mcp/personal/status',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_X_SHELLUI_COMPANY_ID=str(self.company.id),
        )
        self.assertEqual(status.status_code, 200)
        self.assertTrue(status.json()['mcp_enabled'])
        self.assertEqual(status.json()['mcp_url'], self.resource)

        expires = (timezone.now() + timedelta(days=7)).isoformat()
        created = self.client.post(
            '/api/v1/mcp/personal/agents/create',
            data=json.dumps(
                {
                    'name': 'My CLI',
                    'services': ['identity', 'storage'],
                    'access_mode': 'read_only',
                    'read_level': 'safe',
                    'allow_destructive': False,
                    'expires_at': expires,
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_X_SHELLUI_COMPANY_ID=str(self.company.id),
        )
        self.assertEqual(created.status_code, 201, created.content)
        body = created.json()
        self.assertIn('access_token', body)
        agent_id = body['agent']['id']
        self.assertEqual(body['agent']['kind'], 'personal')
        claims = jwt.decode(body['access_token'], options={'verify_signature': False})
        self.assertEqual(claims['company_id'], self.company.id)
        self.assertEqual(claims['aud'], self.resource)
        self.assertIn('personal_token_id', claims)

        listed = self.client.get(
            '/api/v1/mcp/personal/agents',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_X_SHELLUI_COMPANY_ID=str(self.company.id),
        )
        self.assertEqual(len(listed.json()['agents']), 1)

        McpCallLog.objects.create(
            agent=Agent.objects.get(pk=agent_id),
            company=self.company,
            service='ai',
            tool='tools/list',
            status_code=200,
            client_ip='203.0.113.1',
            result='success',
            arguments_redacted={'secret': 'must-not-appear'},
        )
        activity = self.client.get(
            f'/api/v1/mcp/personal/agents/{agent_id}/activity',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_X_SHELLUI_COMPANY_ID=str(self.company.id),
        )
        self.assertEqual(activity.status_code, 200)
        row = activity.json()['activity'][0]
        self.assertEqual(row['tool'], 'tools/list')
        self.assertEqual(row['client_ip'], '203.0.113.1')
        self.assertNotIn('arguments', json.dumps(activity.json()))

        revoked = self.client.post(
            f'/api/v1/mcp/personal/agents/{agent_id}/revoke',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_X_SHELLUI_COMPANY_ID=str(self.company.id),
        )
        self.assertIsNotNone(revoked.json()['agent']['revoked_at'])
        self.assertFalse(Agent.objects.get(pk=agent_id).is_active)

    def test_staff_cannot_create(self):
        staff = User.objects.create_user(username='st', email='st@acme.com', password='unused', is_staff=True)
        set_company_access(self.company, staff, enabled=True)
        from apps.authapi.views import _issue_shellui_tokens

        token = _issue_shellui_tokens(staff, company=self.company)['access_token']
        response = self.client.post(
            '/api/v1/mcp/personal/agents/create',
            data=json.dumps(
                {
                    'name': 'Nope',
                    'services': ['identity'],
                    'expires_at': (timezone.now() + timedelta(days=1)).isoformat(),
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_X_SHELLUI_COMPANY_ID=str(self.company.id),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(PersonalAgentCredential.objects.count(), 0)

    def test_wrong_company_agent_not_listed(self):
        outsider = User.objects.create_user(username='out', email='out@other.com', password='unused')
        set_company_access(self.other, outsider, enabled=True)
        agent = Agent.objects.create(
            company=self.other,
            name='Other agent',
            created_by=outsider,
            services_allowed=['ai', 'identity'],
        )
        token = self._member_token()
        listed = self.client.get(
            '/api/v1/mcp/personal/agents',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_X_SHELLUI_COMPANY_ID=str(self.company.id),
        )
        ids = {a['id'] for a in listed.json()['agents']}
        self.assertNotIn(str(agent.id), ids)

    def test_token_audience_bound_to_company(self):
        agent = Agent.objects.create(
            company=self.company,
            name='a',
            created_by=self.user,
            services_allowed=['ai', 'identity'],
        )
        cred_id = PersonalAgentCredential.objects.create(
            agent=agent,
            company=self.company,
            user=self.user,
            name='a',
            token_jti_digest='abc',
            expires_at=timezone.now() + timedelta(days=1),
        ).id
        other_resource = f'https://ai.test/c/{self.other.id}/mcp'
        with self.assertRaises(ValueError):
            encode_personal_agent_access_token(
                agent,
                resource=other_resource,
                expires_at=timezone.now() + timedelta(days=1),
                personal_token_id=cred_id,
                jti='jti',
            )
