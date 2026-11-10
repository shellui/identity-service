"""Contract for identity MCP tools/list: names, input schemas, and required fields."""

from __future__ import annotations

import json
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from drf_spectacular.generators import SchemaGenerator
from shellui_django.mcp.openapi_tools import tools_from_schema

from apps.agents.models import Agent
from apps.agents.tokens import encode_access_token
from apps.authapi.mcp_openapi import MCP_REQUIRED_OPERATION_IDS
from apps.authapi.openapi_mcp_registry import MCP_SPECS
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

IDENTITY_MCP = 'https://identity.test/mcp'
FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'mcp_tools_list.json'


def _rpc(method: str, **params) -> str:
    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
class McpToolContractTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Contract Co', slug='contract-co')
        self.owner = User.objects.create_user(username='contract-owner', email='owner@contract.test', password='x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        agent = Agent.objects.create(
            company=self.company,
            name='Contract',
            created_by=self.owner,
            access_mode=Agent.ACCESS_FULL,
            read_level=Agent.READ_SENSITIVE,
            services_allowed=['identity'],
        )
        self.token = encode_access_token(agent, resource=IDENTITY_MCP)

    def _tools_list(self) -> list[dict]:
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
        )
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertIn('result', body, body)
        return body['result']['tools']

    def test_tools_list_matches_pinned_schema(self):
        tools = self._tools_list()
        pinned = json.loads(FIXTURE.read_text())
        self.assertEqual(tools, pinned)
        names = [tool['name'] for tool in tools]
        self.assertEqual(names, sorted(names))
        self.assertEqual(set(names), set(MCP_REQUIRED_OPERATION_IDS))
        for tool in tools:
            schema = tool['inputSchema']
            self.assertEqual(schema['type'], 'object')
            self.assertFalse(schema['additionalProperties'], tool['name'])
            self.assertIn('path', schema['required'], tool['name'])
            self.assertIn('method', schema['required'], tool['name'])
            self.assertIn('const', schema['properties']['path'], tool['name'])
            self.assertIn('enum', schema['properties']['method'], tool['name'])

    def test_tool_names_use_identity_prefix(self):
        for tool in self._tools_list():
            name = tool['name']
            self.assertFalse(name.startswith('api_v1_'), name)
            self.assertTrue(name.startswith('identity_'), name)

    def test_access_flags_match_registry(self):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        by_name = {tool['name']: tool for tool in tools_from_schema(schema)}
        self.assertEqual(set(by_name), set(MCP_SPECS))
        for name, spec in MCP_SPECS.items():
            meta = by_name[name]['_meta']
            self.assertEqual(meta['read_only'], spec.read_only, name)
            self.assertEqual(meta['destructive'], spec.destructive, name)
            self.assertTrue(meta['mcp_tagged'], name)
