"""Contract for identity MCP tools/list: names, input schemas, and required fields."""

from __future__ import annotations

import json
import re
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from drf_spectacular.generators import SchemaGenerator
from shellui_django.mcp.openapi_tools import tools_from_schema

from apps.agents.models import Agent
from apps.agents.tokens import encode_access_token
from apps.authapi.mcp_openapi import MCP_REQUIRED_OPERATION_IDS
from apps.authapi.mcp_parameter_schema import (
    ACCESS_MODE_VALUES,
    ACCESS_VALUES,
    DELIVERY_STATUS_VALUES,
    LANGUAGE_VALUES,
    REDIRECT_SOURCE_VALUES,
    ROLE_VALUES,
    catalog_event_ids,
    provider_slugs,
    webhook_event_ids,
)
from apps.authapi.openapi_mcp_registry import MCP_SPECS
from apps.companies.access import set_company_access
from apps.companies.models import Company

# Writes that do not delete, revoke, change access, or send data outside.
# Creating or updating a webhook rule only stores the rule. Nothing is sent until an event fires.
NON_DESTRUCTIVE_WRITES = frozenset(
    {
        'identity_create_action_rules',
        'identity_create_groups',
        'identity_replace_groups',
        'identity_update_action_rules',
        'identity_update_groups',
    }
)
TRANSPORT_ARGUMENT_NAMES = frozenset({'method', 'path', 'query', 'body', 'path_params', 'format'})
_BANNED_DESCRIPTION = re.compile(
    r'\b(easy|simple|quick|just|very|really|simply|seamless|robust|powerful)\b',
    re.I,
)

User = get_user_model()

IDENTITY_MCP = 'https://identity.test/mcp'
FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'mcp_tools_list.json'


def _operation(schema: dict, operation_id: str) -> dict:
    for path_item in schema['paths'].values():
        for operation in path_item.values():
            if isinstance(operation, dict) and operation.get('operationId') == operation_id:
                return operation
    raise AssertionError(operation_id)


def _body(operation: dict, schema: dict) -> tuple[dict, list]:
    content = (operation.get('requestBody') or {}).get('content') or {}
    body_schema = (content.get('application/json') or {}).get('schema') or {}
    if '$ref' in body_schema:
        name = body_schema['$ref'].rsplit('/', 1)[-1]
        body_schema = schema['components']['schemas'][name]
    return body_schema.get('properties') or {}, list(body_schema.get('required') or [])


def _argument_schema(operation: dict, schema: dict, field: str) -> dict | None:
    for param in operation.get('parameters') or []:
        if isinstance(param, dict) and param.get('name') == field:
            found = param.get('schema')
            return found if isinstance(found, dict) else None
    props, _required = _body(operation, schema)
    found = props.get(field)
    return found if isinstance(found, dict) else None


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
            self.assertEqual(schema['type'], 'object', tool['name'])
            self.assertFalse(schema['additionalProperties'], tool['name'])
            self.assertTrue(TRANSPORT_ARGUMENT_NAMES.isdisjoint(schema['properties']), tool['name'])
            self.assertTrue(TRANSPORT_ARGUMENT_NAMES.isdisjoint(schema.get('required') or []), tool['name'])

    def test_tool_descriptions_and_risk_annotations(self):
        by_name = {tool['name']: tool for tool in self._tools_list()}
        self.assertEqual(set(by_name), set(MCP_SPECS))
        destructive = set()
        read_only = set()
        for name, spec in MCP_SPECS.items():
            tool = by_name[name]
            description = tool['description']
            self.assertEqual(description, spec.summary, name)
            self.assertLessEqual(description.count('.'), 2, name)
            self.assertGreaterEqual(description.count('.'), 1, name)
            self.assertNotIn('—', description, name)
            self.assertNotIn('–', description, name)
            self.assertNotIn('ShellUI', description, name)
            self.assertNotIn('ShellUi', description, name)
            self.assertIsNone(_BANNED_DESCRIPTION.search(description), name)
            annotations = tool['annotations']
            self.assertEqual(annotations['readOnlyHint'], spec.read_only, name)
            self.assertEqual(annotations['destructiveHint'], spec.destructive, name)
            self.assertFalse(spec.read_only and spec.destructive, name)
            if spec.read_only:
                read_only.add(name)
            if spec.destructive:
                destructive.add(name)
        self.assertTrue(destructive.isdisjoint(read_only))
        self.assertTrue(NON_DESTRUCTIVE_WRITES.isdisjoint(destructive))
        self.assertTrue(NON_DESTRUCTIVE_WRITES.isdisjoint(read_only))
        self.assertEqual(destructive | read_only | NON_DESTRUCTIVE_WRITES, set(MCP_SPECS))

    def test_fixed_values_are_enums_on_tools_and_openapi(self):
        tools = {tool['name']: tool for tool in self._tools_list()}
        schema = SchemaGenerator().get_schema(request=None, public=True)
        self._assert_tool_enum(tools, 'identity_get_users_audience', 'access', ACCESS_VALUES)
        self._assert_tool_enum(
            tools,
            'identity_get_users_audience',
            'roles',
            ROLE_VALUES,
            array=True,
        )
        self._assert_tool_enum(tools, 'identity_list_action_deliveries', 'status', DELIVERY_STATUS_VALUES)
        self._assert_tool_enum(tools, 'identity_list_action_deliveries', 'event_type', webhook_event_ids())
        self._assert_tool_enum(tools, 'identity_list_events', 'event_type', catalog_event_ids(), array=True)
        self._assert_tool_enum(tools, 'identity_list_events', 'scope', ['company', 'platform'])
        self._assert_tool_enum(tools, 'identity_create_invitations', 'language', LANGUAGE_VALUES)
        self._assert_tool_enum(tools, 'identity_create_action_rules', 'event_type', webhook_event_ids())
        self._assert_tool_enum(tools, 'identity_update_action_rules', 'event_type', webhook_event_ids())
        self._assert_tool_enum(tools, 'identity_create_oauth_social_apps', 'docs_slug', provider_slugs())
        self._assert_tool_enum(tools, 'identity_create_oauth_social_apps', 'provider', provider_slugs())
        self._assert_tool_enum(tools, 'identity_replace_companies', 'access_mode', ACCESS_MODE_VALUES)
        self._assert_tool_enum(tools, 'identity_update_companies', 'access_mode', ACCESS_MODE_VALUES)
        self._assert_tool_enum(tools, 'identity_create_oauth_redirects', 'source', REDIRECT_SOURCE_VALUES)
        self.assertIn('identity.user.created', webhook_event_ids())
        self.assertIn('github', provider_slugs())

        for operation_id, field, expected in (
            ('identity_get_users_audience', 'access', ACCESS_VALUES),
            ('identity_list_action_deliveries', 'status', DELIVERY_STATUS_VALUES),
            ('identity_create_invitations', 'language', LANGUAGE_VALUES),
            ('identity_create_action_rules', 'event_type', webhook_event_ids()),
            ('identity_delete_hosting_oauth_redirects', 'base_url', None),
        ):
            operation = _operation(schema, operation_id)
            if field == 'base_url':
                props, required = _body(operation, schema)
                self.assertIn('base_url', props, operation_id)
                self.assertIn('base_url', required, operation_id)
                self.assertTrue(props['base_url'].get('description'), operation_id)
                continue
            prop = _argument_schema(operation, schema, field)
            self.assertIsNotNone(prop, (operation_id, field))
            assert prop is not None
            if prop.get('type') == 'array':
                self.assertEqual(prop['items'].get('enum'), expected, (operation_id, field))
            else:
                self.assertEqual(prop.get('enum'), expected, (operation_id, field))
            self.assertTrue(prop.get('description'), (operation_id, field))
            self.assertNotIn('method', {param.get('name') for param in operation.get('parameters') or []})
            self.assertNotIn('path', {param.get('name') for param in operation.get('parameters') or []})
            self.assertNotIn('format', {param.get('name') for param in operation.get('parameters') or []})

        users = tools['identity_get_users']['inputSchema']['properties']['id']
        self.assertIn('user id', users.get('description', '').lower())
        self.assertIn('id', tools['identity_delete_users']['inputSchema']['required'])
        create_group = tools['identity_create_groups']['inputSchema']
        self.assertEqual(create_group['required'], ['display_name'])

    def _assert_tool_enum(self, tools, name, field, expected, *, array=False):
        prop = tools[name]['inputSchema']['properties'][field]
        self.assertTrue(prop.get('description'), (name, field))
        self.assertNotIn('—', prop['description'], (name, field))
        self.assertNotIn('–', prop['description'], (name, field))
        if array:
            self.assertEqual(prop['type'], 'array', (name, field))
            self.assertEqual(prop['items'].get('enum'), expected, (name, field))
        else:
            self.assertEqual(prop.get('enum'), expected, (name, field))

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
