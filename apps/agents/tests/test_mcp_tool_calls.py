"""Happy-path tools/call coverage for every identity MCP tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.test import TestCase, override_settings

from apps.actions.models import ActionOutbox, ActionRule
from apps.actions.webhook_signing import generate_webhook_signing_secret
from apps.actions.webhook_transport import WebhookPostResult
from apps.agents.models import Agent, McpApprovalRequest, McpCallLog
from apps.agents.tokens import encode_access_token
from apps.authapi.models import PersonalAccessToken
from apps.authapi.openapi_mcp_registry import MCP_SPECS
from apps.companies.access import set_company_access
from apps.companies.models import (
    Company,
    CompanyGroup,
    CompanyInvitation,
    CompanyOAuthClient,
    CompanyOAuthRedirect,
)
from apps.scim.models import CompanyScimToken

User = get_user_model()

IDENTITY_MCP = 'https://identity.test/mcp'


def _rpc(method: str, **params) -> str:
    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})


@override_settings(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AI_SERVICE_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    MAGIC_LINK_ENABLED=True,
)
class McpToolCallTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Tool Co', slug='tool-co', enable_magic_link=True)
        self.owner = User.objects.create_user(
            username='tool-owner',
            email='owner@tool.test',
            password='x',
            first_name='Ada',
            last_name='Lovelace',
        )
        self.member = User.objects.create_user(
            username='tool-member',
            email='member@tool.test',
            password='x',
            first_name='Grace',
        )
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.member, enabled=True)
        self.agent = Agent.objects.create(
            company=self.company,
            name='Caller',
            created_by=self.owner,
            access_mode=Agent.ACCESS_FULL,
            read_level=Agent.READ_SENSITIVE,
            services_allowed=['identity'],
        )
        self.token = encode_access_token(self.agent, resource=IDENTITY_MCP)
        self.group = CompanyGroup.objects.create(company=self.company, display_name='Ops')
        self.event = self._event()
        self.pending_invite = CompanyInvitation.objects.create(
            company=self.company,
            email='pending@tool.test',
            invited_by=self.owner,
        )
        self.revoked_invite = CompanyInvitation.objects.create(
            company=self.company,
            email='revoked@tool.test',
            status=CompanyInvitation.STATUS_REVOKED,
            invited_by=self.owner,
        )
        self.rule_secret = generate_webhook_signing_secret()
        self.rule = ActionRule.objects.create(
            company=self.company,
            name='Hook',
            event_type='identity.user.created',
            config={'url': 'https://hooks.example.com/h', 'secret': self.rule_secret},
        )
        self.delivery = ActionOutbox.objects.create(
            company=self.company,
            action_rule=self.rule,
            event_type='identity.user.created',
            envelope={'id': 'wh_1', 'type': 'identity.user.created'},
            status=ActionOutbox.STATUS_FAILED,
        )
        self.redirect = CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://manual.example.com',
            label='Manual',
        )
        self.hosting_redirect = CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://preview.example.com',
            source=CompanyOAuthRedirect.SOURCE_HOSTING,
            label='Preview',
        )
        self.pat = PersonalAccessToken.objects.create(
            company=self.company,
            user=self.owner,
            jti='pat-jti-1',
            name='ci',
        )
        self.scim = CompanyScimToken.objects.create(
            company=self.company,
            token_prefix='scimprefix',
            token_hash='a' * 64,
            name='ci',
        )
        self.social_app = self._social_app('github', 'cid-github')
        self.mapping = CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.social_app,
            is_active=True,
        )
        self.tools = {tool['name']: tool for tool in self._tools_list()}

    def _event(self):
        from apps.actions.models import EventLog

        return EventLog.objects.create(
            company=self.company,
            user=self.owner,
            event_type='identity.user.invited',
            data={'email': 'pending@tool.test'},
        )

    def _social_app(self, slug: str, client_id: str) -> SocialApp:
        app = SocialApp.objects.create(
            provider=slug,
            name=slug,
            client_id=client_id,
            secret='secret',
            settings={'catalog_slug': slug, 'created_by_company_id': self.company.id},
        )
        app.sites.add(Site.objects.get_current())
        return app

    def _tools_list(self) -> list[dict]:
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()['result']['tools']

    def _post(self, name: str, arguments: dict) -> dict:
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/call', name=name, arguments=arguments),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
        )
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertIn('result', body, body)
        return body

    def _arguments(self, name: str, *, path_params=None, body=None, query=None) -> dict:
        tool = self.tools[name]
        props = tool['inputSchema']['properties']
        arguments = {
            'path': props['path']['const'],
            'method': props['method']['enum'][0],
        }
        required = props.get('path_params', {}).get('required') or []
        if required:
            self.assertIsNotNone(path_params, name)
            arguments['path_params'] = {key: str(path_params[key]) for key in required}
        if body is not None:
            arguments['body'] = body
        if query is not None:
            arguments['query'] = query
        return arguments

    def _needs_approval(self, payload: dict) -> bool:
        result = payload['result']
        text = (result.get('content') or [{}])[0].get('text') or ''
        meta = result.get('meta') or {}
        return bool(result.get('isError') and meta.get('status') == 'pending' and 'Approval required' in text)

    def call(self, name: str, *, path_params=None, body=None, query=None) -> dict:
        arguments = self._arguments(name, path_params=path_params, body=body, query=query)
        payload = self._post(name, arguments)
        if MCP_SPECS[name].destructive:
            self.assertTrue(self._needs_approval(payload), payload)
            approval_id = payload['result']['meta']['approval_id']
            updated = McpApprovalRequest.objects.filter(pk=approval_id).update(
                status=McpApprovalRequest.STATUS_APPROVED,
            )
            self.assertEqual(updated, 1)
            payload = self._post(name, arguments)
        else:
            self.assertFalse(self._needs_approval(payload), payload)
        result = payload['result']
        self.assertFalse(result.get('isError'), result)
        return json.loads(result['content'][0]['text'])


def _bind_tool_tests() -> None:
    def _make(tool_name: str):
        def test(self):
            TOOL_CALLS[tool_name](self)

        test.__name__ = f'test_{tool_name}'
        test.__doc__ = f'Happy-path tools/call for {tool_name}.'
        return test

    for tool_name in TOOL_CALLS:
        setattr(McpToolCallTests, f'test_{tool_name}', _make(tool_name))


def _users_list(self):
    body = self.call('api_v1_users_list')
    self.assertIn('owner@tool.test', json.dumps(body))


def _users_retrieve(self):
    body = self.call('api_v1_users_retrieve', path_params={'id': self.member.pk})
    self.assertEqual(body['id'], self.member.pk)


def _users_update(self):
    body = self.call(
        'api_v1_users_update',
        path_params={'id': self.member.pk},
        body={'first_name': 'Graceful'},
    )
    self.assertEqual(body['first_name'], 'Graceful')


def _users_destroy(self):
    self.call('api_v1_users_destroy', path_params={'id': self.member.pk})
    self.assertFalse(self.company.members.filter(pk=self.member.pk).exists())


def _users_audience(self):
    body = self.call('api_v1_users_audience')
    self.assertGreaterEqual(body.get('count', 0), 1)


def _groups_list(self):
    body = self.call('api_v1_groups_list')
    self.assertIn('Ops', json.dumps(body))


def _groups_create(self):
    body = self.call('api_v1_groups_create', body={'display_name': 'New group'})
    self.assertEqual(body['display_name'], 'New group')


def _groups_retrieve(self):
    body = self.call('api_v1_groups_retrieve', path_params={'id': self.group.pk})
    self.assertEqual(body['display_name'], 'Ops')


def _groups_update(self):
    body = self.call(
        'api_v1_groups_update',
        path_params={'id': self.group.pk},
        body={'display_name': 'Renamed'},
    )
    self.assertEqual(body['display_name'], 'Renamed')


def _groups_partial_update(self):
    body = self.call(
        'api_v1_groups_partial_update',
        path_params={'id': self.group.pk},
        body={'display_name': 'Patched'},
    )
    self.assertEqual(body['display_name'], 'Patched')


def _groups_destroy(self):
    self.call('api_v1_groups_destroy', path_params={'id': self.group.pk})
    self.assertFalse(CompanyGroup.objects.filter(pk=self.group.pk).exists())


def _oauth_clients_list(self):
    body = self.call('api_v1_oauth_clients_list')
    self.assertIn(str(self.mapping.pk), json.dumps(body))


def _oauth_clients_create(self):
    app = self._social_app('gitlab', 'cid-gitlab')
    body = self.call('api_v1_oauth_clients_create', body={'social_app_id': app.pk, 'is_active': True})
    self.assertEqual(body['social_app_id'], app.pk)


def _oauth_clients_retrieve(self):
    body = self.call('api_v1_oauth_clients_retrieve', path_params={'id': self.mapping.pk})
    self.assertEqual(body['id'], self.mapping.pk)


def _oauth_clients_update(self):
    body = self.call(
        'api_v1_oauth_clients_update',
        path_params={'id': self.mapping.pk},
        body={'is_active': True},
    )
    self.assertTrue(body['is_active'])


def _oauth_clients_destroy(self):
    self.call('api_v1_oauth_clients_destroy', path_params={'id': self.mapping.pk})
    self.assertFalse(CompanyOAuthClient.objects.filter(pk=self.mapping.pk).exists())


def _oauth_redirects_list(self):
    body = self.call('api_v1_oauth_redirects_list')
    self.assertIn('https://manual.example.com', json.dumps(body))


def _oauth_redirects_create(self):
    body = self.call(
        'api_v1_oauth_redirects_create',
        body={'base_url': 'https://new.example.com', 'label': 'New'},
    )
    self.assertEqual(body['base_url'], 'https://new.example.com')


def _oauth_redirects_retrieve(self):
    body = self.call('api_v1_oauth_redirects_retrieve', path_params={'id': self.redirect.pk})
    self.assertEqual(body['id'], self.redirect.pk)


def _oauth_redirects_partial_update(self):
    body = self.call(
        'api_v1_oauth_redirects_partial_update',
        path_params={'id': self.redirect.pk},
        body={'label': 'Updated'},
    )
    self.assertEqual(body['label'], 'Updated')


def _oauth_redirects_destroy(self):
    self.call('api_v1_oauth_redirects_destroy', path_params={'id': self.redirect.pk})
    self.assertFalse(CompanyOAuthRedirect.objects.filter(pk=self.redirect.pk).exists())


def _oauth_social_apps_list(self):
    body = self.call('api_v1_oauth_social_apps_list')
    self.assertIn('github', json.dumps(body))


def _oauth_social_apps_create(self):
    body = self.call(
        'api_v1_oauth_social_apps_create',
        body={'docs_slug': 'gitlab', 'client_id': 'cid-new', 'client_secret': 'super-secret'},
    )
    self.assertEqual(body['social_app']['provider'], 'gitlab')
    logged = McpCallLog.objects.filter(tool='api_v1_oauth_social_apps_create').get()
    self.assertEqual(logged.arguments_redacted['body']['client_secret'], '[redacted]')
    self.assertNotIn('super-secret', json.dumps(logged.arguments_redacted))


def _oauth_social_apps_update(self):
    body = self.call(
        'api_v1_oauth_social_apps_update',
        path_params={'id': self.social_app.pk},
        body={'client_id': 'cid-github-2'},
    )
    self.assertEqual(body['client_id'], 'cid-github-2')


def _oauth_social_apps_destroy(self):
    self.call('api_v1_oauth_social_apps_destroy', path_params={'id': self.social_app.pk})
    self.assertFalse(SocialApp.objects.filter(pk=self.social_app.pk).exists())


def _oauth_provider_catalog(self):
    body = self.call('api_v1_oauth_provider_catalog_retrieve')
    self.assertIn('github', json.dumps(body))


def _hosting_update(self):
    body = self.call(
        'api_v1_hosting_oauth_redirects_update',
        body={'base_url': 'https://host.example.com', 'label': 'Host'},
    )
    self.assertEqual(body['base_url'], 'https://host.example.com')
    self.assertEqual(body['source'], 'hosting')


def _hosting_destroy(self):
    self.call(
        'api_v1_hosting_oauth_redirects_destroy',
        body={'base_url': 'https://preview.example.com'},
    )
    self.assertFalse(
        CompanyOAuthRedirect.objects.filter(
            company=self.company,
            base_url='https://preview.example.com',
        ).exists()
    )


def _auth_methods_retrieve(self):
    body = self.call('api_v1_auth_methods_retrieve')
    self.assertTrue(body['enable_magic_link'])


def _auth_methods_partial_update(self):
    body = self.call('api_v1_auth_methods_partial_update', body={'enable_magic_link': False})
    self.assertFalse(body['enable_magic_link'])


def _auth_methods_update(self):
    body = self.call('api_v1_auth_methods_update', body={'enable_magic_link': True})
    self.assertTrue(body['enable_magic_link'])


def _scim_status(self):
    body = self.call('api_v1_scim_status')
    self.assertIn('scim', json.dumps(body).lower())


def _scim_tokens_list(self):
    body = self.call('api_v1_scim_tokens_list')
    self.assertIn('scimprefix', json.dumps(body))


def _scim_tokens_create(self):
    body = self.call('api_v1_scim_tokens_create', body={'name': 'minted'})
    self.assertEqual(body.get('token'), '[redacted]')
    self.assertEqual(body.get('name'), 'minted')
    self.assertTrue(CompanyScimToken.objects.filter(company=self.company, name='minted', revoked_at__isnull=True).exists())


def _scim_tokens_revoke(self):
    self.call('api_v1_scim_tokens_revoke', path_params={'token_id': self.scim.pk})
    self.scim.refresh_from_db()
    self.assertIsNotNone(self.scim.revoked_at)


def _pat_list(self):
    body = self.call('api_v1_personal_access_tokens_list')
    self.assertIn(str(self.pat.pk), json.dumps(body))


def _pat_create(self):
    body = self.call('api_v1_personal_access_tokens_create', body={'name': 'minted', 'read_only': True})
    self.assertEqual(body.get('access_token'), '[redacted]')
    self.assertTrue(body['read_only'])
    self.assertEqual(body['name'], 'minted')
    self.assertTrue(
        PersonalAccessToken.objects.filter(company=self.company, user=self.owner, name='minted').exists()
    )


def _pat_revoke(self):
    self.call('api_v1_personal_access_tokens_revoke', path_params={'key_id': self.pat.pk})
    self.pat.refresh_from_db()
    self.assertIsNotNone(self.pat.revoked_at)


def _companies_list(self):
    body = self.call('api_v1_companies_list')
    self.assertIn('Tool Co', json.dumps(body))


def _companies_retrieve(self):
    body = self.call('api_v1_companies_retrieve', path_params={'id': self.company.pk})
    self.assertEqual(body['id'], self.company.pk)


def _companies_update(self):
    body = self.call(
        'api_v1_companies_update',
        path_params={'id': self.company.pk},
        body={'name': 'Tool Co Renamed'},
    )
    self.assertEqual(body['name'], 'Tool Co Renamed')


def _companies_partial_update(self):
    body = self.call(
        'api_v1_companies_partial_update',
        path_params={'id': self.company.pk},
        body={'name': 'Tool Co Patched'},
    )
    self.assertEqual(body['name'], 'Tool Co Patched')


def _invitations_list(self):
    body = self.call('api_v1_invitations_list')
    self.assertIn('pending@tool.test', json.dumps(body))


def _invitations_create(self):
    body = self.call(
        'api_v1_invitations_create',
        body={'email': 'new@tool.test', 'language': 'en'},
    )
    self.assertEqual(body['invitation']['email'], 'new@tool.test')


def _invitations_revoke(self):
    body = self.call('api_v1_invitations_revoke', path_params={'id': self.pending_invite.pk})
    self.assertEqual(body['invitation']['status'], 'revoked')


def _invitations_destroy(self):
    self.call('api_v1_invitations_destroy', path_params={'id': self.revoked_invite.pk})
    self.assertFalse(CompanyInvitation.objects.filter(pk=self.revoked_invite.pk).exists())


def _events_list(self):
    body = self.call('api_v1_events_list')
    self.assertGreaterEqual(body.get('count', 0), 1)


def _events_retrieve(self):
    body = self.call('api_v1_events_retrieve', path_params={'id': self.event.pk})
    self.assertEqual(body['id'], self.event.pk)


def _events_types(self):
    body = self.call('api_v1_events_types_list')
    self.assertTrue(body)


def _events_retention(self):
    body = self.call('api_v1_events_retention_retrieve')
    self.assertIn('retention', json.dumps(body).lower())


def _actions_events(self):
    body = self.call('api_v1_actions_events_list')
    self.assertIn('identity.user.created', json.dumps(body))


def _actions_rules_list(self):
    body = self.call('api_v1_actions_rules_list')
    row = next(item for item in body['results'] if item['name'] == 'Hook')
    self.assertIs(row['config']['has_secret'], True)
    self.assertNotIn('whsec_test_secret', json.dumps(body))


def _actions_rules_create(self):
    body = self.call(
        'api_v1_actions_rules_create',
        body={
            'name': 'Created',
            'event_type': 'identity.user.created',
            'url': 'https://hooks.example.com/created',
        },
    )
    self.assertEqual(body.get('secret'), '[redacted]')
    self.assertIs(body['config']['has_secret'], True)
    stored = ActionRule.objects.get(company=self.company, name='Created').config['secret']
    self.assertTrue(stored)
    self.assertNotIn(stored, json.dumps(body))


def _actions_rules_retrieve(self):
    body = self.call('api_v1_actions_rules_retrieve', path_params={'id': self.rule.pk})
    self.assertEqual(body['name'], 'Hook')
    self.assertIs(body['config']['has_secret'], True)
    self.assertNotIn('secret', body)


def _actions_rules_partial_update(self):
    body = self.call(
        'api_v1_actions_rules_partial_update',
        path_params={'id': self.rule.pk},
        body={'name': 'Hook renamed'},
    )
    self.assertEqual(body['name'], 'Hook renamed')


def _actions_rules_destroy(self):
    self.call('api_v1_actions_rules_destroy', path_params={'id': self.rule.pk})
    self.assertFalse(ActionRule.objects.filter(pk=self.rule.pk).exists())


def _actions_rules_rotate_secret(self):
    body = self.call('api_v1_actions_rules_rotate_secret', path_params={'id': self.rule.pk})
    self.assertEqual(body.get('secret'), '[redacted]')
    self.rule.refresh_from_db()
    stored = self.rule.config['secret']
    self.assertNotEqual(stored, self.rule_secret)
    self.assertNotIn(stored, json.dumps(body))


def _actions_rules_send_test(self):
    with patch(
        'apps.actions.handlers.webhook.post_webhook_url',
        return_value=WebhookPostResult(status=204, excerpt=''),
    ):
        body = self.call('api_v1_actions_rules_send_test', path_params={'id': self.rule.pk})
    self.assertTrue(body.get('ok'))


def _actions_deliveries_list(self):
    body = self.call('api_v1_actions_deliveries_list')
    self.assertGreaterEqual(body.get('count', 0), 1)


def _actions_deliveries_retrieve(self):
    body = self.call('api_v1_actions_deliveries_retrieve', path_params={'delivery_id': self.delivery.pk})
    self.assertEqual(body['id'], str(self.delivery.pk))


def _actions_deliveries_requeue(self):
    body = self.call('api_v1_actions_deliveries_requeue', path_params={'delivery_id': self.delivery.pk})
    self.assertEqual(body['status'], 'pending')


def _services_list(self):
    body = self.call('api_v1_mcp_services_list')
    by_id = {item['id']: item['mcp_url'] for item in body['services']}
    self.assertEqual(by_id['identity'], 'https://identity.test/mcp')
    self.assertEqual(by_id['ai'], f'https://ai.test/c/{self.company.pk}/mcp')


TOOL_CALLS = {
    'api_v1_actions_deliveries_list': _actions_deliveries_list,
    'api_v1_actions_deliveries_requeue': _actions_deliveries_requeue,
    'api_v1_actions_deliveries_retrieve': _actions_deliveries_retrieve,
    'api_v1_actions_events_list': _actions_events,
    'api_v1_actions_rules_create': _actions_rules_create,
    'api_v1_actions_rules_destroy': _actions_rules_destroy,
    'api_v1_actions_rules_list': _actions_rules_list,
    'api_v1_actions_rules_partial_update': _actions_rules_partial_update,
    'api_v1_actions_rules_retrieve': _actions_rules_retrieve,
    'api_v1_actions_rules_rotate_secret': _actions_rules_rotate_secret,
    'api_v1_actions_rules_send_test': _actions_rules_send_test,
    'api_v1_auth_methods_partial_update': _auth_methods_partial_update,
    'api_v1_auth_methods_retrieve': _auth_methods_retrieve,
    'api_v1_auth_methods_update': _auth_methods_update,
    'api_v1_companies_list': _companies_list,
    'api_v1_companies_partial_update': _companies_partial_update,
    'api_v1_companies_retrieve': _companies_retrieve,
    'api_v1_companies_update': _companies_update,
    'api_v1_events_list': _events_list,
    'api_v1_events_retention_retrieve': _events_retention,
    'api_v1_events_retrieve': _events_retrieve,
    'api_v1_events_types_list': _events_types,
    'api_v1_groups_create': _groups_create,
    'api_v1_groups_destroy': _groups_destroy,
    'api_v1_groups_list': _groups_list,
    'api_v1_groups_partial_update': _groups_partial_update,
    'api_v1_groups_retrieve': _groups_retrieve,
    'api_v1_groups_update': _groups_update,
    'api_v1_hosting_oauth_redirects_destroy': _hosting_destroy,
    'api_v1_hosting_oauth_redirects_update': _hosting_update,
    'api_v1_invitations_create': _invitations_create,
    'api_v1_invitations_destroy': _invitations_destroy,
    'api_v1_invitations_list': _invitations_list,
    'api_v1_invitations_revoke': _invitations_revoke,
    'api_v1_mcp_services_list': _services_list,
    'api_v1_oauth_clients_create': _oauth_clients_create,
    'api_v1_oauth_clients_destroy': _oauth_clients_destroy,
    'api_v1_oauth_clients_list': _oauth_clients_list,
    'api_v1_oauth_clients_retrieve': _oauth_clients_retrieve,
    'api_v1_oauth_clients_update': _oauth_clients_update,
    'api_v1_oauth_provider_catalog_retrieve': _oauth_provider_catalog,
    'api_v1_oauth_redirects_create': _oauth_redirects_create,
    'api_v1_oauth_redirects_destroy': _oauth_redirects_destroy,
    'api_v1_oauth_redirects_list': _oauth_redirects_list,
    'api_v1_oauth_redirects_partial_update': _oauth_redirects_partial_update,
    'api_v1_oauth_redirects_retrieve': _oauth_redirects_retrieve,
    'api_v1_oauth_social_apps_create': _oauth_social_apps_create,
    'api_v1_oauth_social_apps_destroy': _oauth_social_apps_destroy,
    'api_v1_oauth_social_apps_list': _oauth_social_apps_list,
    'api_v1_oauth_social_apps_update': _oauth_social_apps_update,
    'api_v1_personal_access_tokens_create': _pat_create,
    'api_v1_personal_access_tokens_list': _pat_list,
    'api_v1_personal_access_tokens_revoke': _pat_revoke,
    'api_v1_scim_status': _scim_status,
    'api_v1_scim_tokens_create': _scim_tokens_create,
    'api_v1_scim_tokens_list': _scim_tokens_list,
    'api_v1_scim_tokens_revoke': _scim_tokens_revoke,
    'api_v1_users_audience': _users_audience,
    'api_v1_users_destroy': _users_destroy,
    'api_v1_users_list': _users_list,
    'api_v1_users_retrieve': _users_retrieve,
    'api_v1_users_update': _users_update,
}


def test_every_exposed_tool_has_a_call_test(self):
    self.assertEqual(set(TOOL_CALLS), set(self.tools))


def test_read_only_agent_cannot_write(self):
    self.agent.access_mode = Agent.ACCESS_READ_ONLY
    self.agent.save(update_fields=['access_mode'])
    self.token = encode_access_token(self.agent, resource=IDENTITY_MCP)
    payload = self._post(
        'api_v1_groups_create',
        self._arguments('api_v1_groups_create', body={'display_name': 'Blocked'}),
    )
    text = payload['result']['content'][0]['text']
    self.assertTrue(payload['result'].get('isError'))
    self.assertIn('read only', text.lower())
    self.assertFalse(CompanyGroup.objects.filter(display_name='Blocked').exists())


def test_other_company_user_is_hidden(self):
    other = Company.objects.create(name='Other', slug='other-co')
    stranger = User.objects.create_user(username='stranger', email='stranger@other.test', password='x')
    set_company_access(other, stranger, enabled=True)
    payload = self._post(
        'api_v1_users_retrieve',
        self._arguments('api_v1_users_retrieve', path_params={'id': stranger.pk}),
    )
    self.assertTrue(payload['result'].get('isError'))
    self.assertNotIn('stranger@other.test', payload['result']['content'][0]['text'])


def test_ask_mode_write_runs_after_approval(self):
    self.agent.access_mode = Agent.ACCESS_ASK
    self.agent.save(update_fields=['access_mode'])
    self.token = encode_access_token(self.agent, resource=IDENTITY_MCP)
    arguments = self._arguments('api_v1_groups_create', body={'display_name': 'Asked'})
    first = self._post('api_v1_groups_create', arguments)
    self.assertTrue(self._needs_approval(first), first)
    McpApprovalRequest.objects.filter(pk=first['result']['meta']['approval_id']).update(
        status=McpApprovalRequest.STATUS_APPROVED,
    )
    second = self._post('api_v1_groups_create', arguments)
    self.assertFalse(second['result'].get('isError'), second)
    self.assertTrue(CompanyGroup.objects.filter(company=self.company, display_name='Asked').exists())


def test_safe_read_masks_email(self):
    self.agent.read_level = Agent.READ_SAFE
    self.agent.save(update_fields=['read_level'])
    self.token = encode_access_token(self.agent, resource=IDENTITY_MCP)
    body = self.call('api_v1_users_list')
    dumped = json.dumps(body)
    self.assertNotIn('owner@tool.test', dumped)
    self.assertIn('[redacted]', dumped)


_bind_tool_tests()
McpToolCallTests.test_every_exposed_tool_has_a_call_test = test_every_exposed_tool_has_a_call_test
McpToolCallTests.test_read_only_agent_cannot_write = test_read_only_agent_cannot_write
McpToolCallTests.test_other_company_user_is_hidden = test_other_company_user_is_hidden
McpToolCallTests.test_ask_mode_write_runs_after_approval = test_ask_mode_write_runs_after_approval
McpToolCallTests.test_safe_read_masks_email = test_safe_read_masks_email
