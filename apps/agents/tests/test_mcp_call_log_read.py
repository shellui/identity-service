"""Stored MCP call log history stays readable. Ingest and local tool-call writes are gone."""

from __future__ import annotations

import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import NoReverseMatch, reverse
from drf_spectacular.generators import SchemaGenerator

from apps.agents.models import Agent, McpCallLog
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

_REGIONAL_KEYS = {
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


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpCallLogReadTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-logs')
        self.owner = User.objects.create_user(
            username='owner-logs',
            email='logs@acme.com',
            password='unused',
        )
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.agent = Agent.objects.create(company=self.company, name='A1', created_by=self.owner)

    def _owner_token(self):
        from apps.authapi.views import _issue_shellui_tokens

        return _issue_shellui_tokens(self.owner, company=self.company)['access_token']

    def test_ingest_route_is_gone(self):
        with self.assertRaises(NoReverseMatch):
            reverse('mcp-internal-call-log')
        response = self.client.post(
            '/api/v1/mcp/internal/mcp-call-logs',
            data='{}',
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 404)

    def test_owner_lists_stored_rows(self):
        McpCallLog.objects.create(
            agent=self.agent,
            company=self.company,
            service='identity',
            tool='identity_list_users',
            http_method='GET',
            path='/api/v1/users',
            status_code=200,
            duration_ms=4,
            outcome='success',
            access_kind='read',
            arguments_redacted={'body': {'secret': 'keep'}},
        )
        global_agent = uuid.uuid4()
        global_company = uuid.uuid4()
        McpCallLog.objects.create(
            agent=None,
            global_agent_id=global_agent,
            global_company_id=global_company,
            company=self.company,
            service='storage',
            tool='list_buckets',
            http_method='POST',
            path='/mcp',
            status_code=200,
            duration_ms=1,
            outcome='allowed',
            access_kind='read',
            arguments_redacted={},
        )
        listed = self.client.get(
            '/api/v1/mcp/call-logs',
            HTTP_AUTHORIZATION=f'Bearer {self._owner_token()}',
        )
        self.assertEqual(listed.status_code, 200, listed.content)
        rows = listed.json()['call_logs']
        self.assertEqual(len(rows), 2)
        global_row = rows[0]
        self.assertIsNone(global_row['agent_id'])
        self.assertEqual(global_row['agent_audit_scope'], 'global_company')
        self.assertEqual(global_row['global_agent_id'], str(global_agent))
        self.assertEqual(global_row['global_company_id'], str(global_company))
        regional = rows[1]
        self.assertEqual(set(regional.keys()), _REGIONAL_KEYS)
        self.assertEqual(regional['agent_id'], str(self.agent.id))
        self.assertEqual(regional['outcome'], 'allowed')
        self.assertEqual(regional['arguments'], {'body': {'secret': 'keep'}})

    def test_openapi_marks_list_deprecated(self):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        operation = schema['paths']['/api/v1/mcp/call-logs']['get']
        self.assertTrue(operation.get('deprecated'))
        description = operation['description']
        self.assertIn('Deprecated', description)
        self.assertIn('GET /ai/v1/mcp/call-logs', description)
        self.assertNotIn('/api/v1/mcp/internal/mcp-call-logs', schema['paths'])
