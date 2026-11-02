"""Aggregated Identity /mcp gateway: tenant isolation, forwarding, and tool catalog."""

from __future__ import annotations

import json
import logging
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.agents.models import Agent
from apps.agents.tokens import encode_access_token
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

IDENTITY_MCP = 'https://identity.test/mcp'
STORAGE_MCP = 'https://storage.test/mcp'
STORAGE_ORIGIN = 'https://storage.test'


def _rpc(method: str, **params):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}
    return json.dumps(body)


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    STORAGE_SERVICE_URL=STORAGE_ORIGIN,
    AUTH_RATE_LIMIT_ENABLED=False,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'mcp-gateway-tests',
        }
    },
)
class McpGatewayTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company_a = Company.objects.create(name='Co A', slug='co-a-gw')
        self.company_b = Company.objects.create(name='Co B', slug='co-b-gw')
        self.owner_a = User.objects.create_user(username='gw-a', password='unused')
        self.owner_b = User.objects.create_user(username='gw-b', password='unused')
        self.company_a.owners.add(self.owner_a)
        self.company_b.owners.add(self.owner_b)
        set_company_access(self.company_a, self.owner_a, enabled=True)
        set_company_access(self.company_b, self.owner_b, enabled=True)
        self.agent_a = Agent.objects.create(
            company=self.company_a,
            name='Agent A',
            created_by=self.owner_a,
            services_allowed=['identity', 'storage'],
        )
        self.agent_b = Agent.objects.create(
            company=self.company_b,
            name='Agent B',
            created_by=self.owner_b,
            services_allowed=['identity', 'storage'],
        )
        self.token_a = encode_access_token(self.agent_a, resource=IDENTITY_MCP)

    @patch('apps.agents.mcp_gateway.requests.post')
    def test_tools_list_includes_remote_when_downstream_ok(self, post):
        storage_tools = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {'tools': [{'name': 'storage_v1_list_buckets', 'description': 'List buckets'}]},
        }

        def side_effect(url, **kwargs):
            from unittest.mock import Mock

            resp = Mock()
            resp.status_code = 200
            resp.json.return_value = storage_tools
            return resp

        post.side_effect = side_effect
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token_a}',
        )
        self.assertEqual(response.status_code, 200)
        names = {t['name'] for t in response.json()['result']['tools']}
        self.assertIn('storage_v1_list_buckets', names)
        self.assertIn('api_v1_mcp_services_list', names)

    @patch('apps.agents.mcp_gateway.requests.post')
    def test_downstream_failure_omits_remote_tools(self, post):
        post.side_effect = ConnectionError('refused')
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token_a}',
        )
        self.assertEqual(response.status_code, 200)
        names = {t['name'] for t in response.json()['result']['tools']}
        self.assertNotIn('storage_v1_list_buckets', names)
        self.assertIn('api_v1_mcp_services_list', names)

    @patch('apps.agents.mcp_gateway.requests.post')
    def test_collision_adds_service_namespace(self, post):
        dup_tool = {'name': 'shared_tool', 'description': 'dup'}

        def side_effect(url, **kwargs):
            from unittest.mock import Mock

            resp = Mock()
            resp.status_code = 200
            resp.json.return_value = {'jsonrpc': '2.0', 'id': 1, 'result': {'tools': [dup_tool]}}
            return resp

        post.side_effect = side_effect
        with patch(
            'apps.agents.mcp_gateway.tools_from_schema',
            return_value=[{'name': 'shared_tool', 'description': 'local'}],
        ):
            response = self.client.post(
                '/mcp',
                data=_rpc('tools/list'),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {self.token_a}',
            )
        names = [t['name'] for t in response.json()['result']['tools']]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('storage__shared_tool', names)

    @patch('apps.agents.mcp_gateway.requests.post')
    def test_services_allowed_blocks_forward(self, post):
        self.agent_a.services_allowed = ['identity']
        self.agent_a.save(update_fields=['services_allowed'])
        token = encode_access_token(self.agent_a, resource=IDENTITY_MCP)
        with patch(
            'apps.agents.mcp_gateway.tools_from_schema',
            return_value=[],
        ):
            list_resp = self.client.post(
                '/mcp',
                data=_rpc('tools/list'),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
            )
        self.assertEqual(list_resp.status_code, 200)
        post.assert_not_called()
        cache.set(
            'mcp_gateway:route:storage_v1_x',
            {'service_id': 'storage', 'downstream_name': 'storage_v1_x'},
            60,
        )
        call_resp = self.client.post(
            '/mcp',
            data=_rpc('tools/call', name='storage_v1_x', arguments={}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(call_resp.status_code, 200)
        self.assertIn('Forbidden', call_resp.json()['error']['message'])
        post.assert_not_called()

    @patch('apps.agents.mcp_gateway.requests.post')
    def test_tenant_isolation_on_forwarded_call(self, post):
        from unittest.mock import Mock

        downstream = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {'content': [{'type': 'text', 'text': 'ok'}], 'isError': False},
        }
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = downstream
        post.return_value = resp

        cache.set(
            'mcp_gateway:route:storage_v1_run',
            {'service_id': 'storage', 'downstream_name': 'storage_v1_run'},
            60,
        )
        token_b = encode_access_token(self.agent_b, resource=IDENTITY_MCP)
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/call', name='storage_v1_run', arguments={'body': {'company_id': self.company_a.id}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token_b}',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['result']['content'][0]['text'], 'ok')
        self.assertEqual(post.call_count, 1)
        _args, kwargs = post.call_args
        self.assertEqual(_args[0], STORAGE_MCP)
        auth_header = kwargs['headers']['Authorization']
        self.assertTrue(auth_header.startswith('Bearer '))
        import jwt

        downstream_token = auth_header.split(' ', 1)[1]
        payload = jwt.decode(downstream_token, options={'verify_signature': False})
        self.assertEqual(payload['company_id'], self.company_b.id)
        self.assertEqual(payload['agent_id'], str(self.agent_b.id))
        self.assertEqual(payload['aud'], STORAGE_MCP)

    @patch('apps.agents.mcp_gateway.encode_access_token', return_value='mcp-test-token-leak-check')
    @patch('apps.agents.mcp_gateway.requests.post', side_effect=ConnectionError('down'))
    def test_no_token_in_logs(self, _post, _encode):
        with self.assertLogs('apps.agents.mcp_gateway', level='WARNING') as logs:
            self.client.post(
                '/mcp',
                data=_rpc('tools/list'),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {self.token_a}',
            )
        joined = '\n'.join(logs.output)
        self.assertNotIn('mcp-test-token-leak-check', joined)
        self.assertNotIn('Bearer ', joined)

    def test_initialize_lists_connected_services(self):
        response = self.client.post(
            '/mcp',
            data=_rpc('initialize'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token_a}',
        )
        instructions = response.json()['result']['instructions']
        self.assertIn('identity', instructions)
        self.assertIn('storage', instructions)
