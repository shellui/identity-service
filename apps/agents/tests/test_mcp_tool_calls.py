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
    body = self.call('identity_list_users')
    self.assertIn('owner@tool.test', json.dumps(body))


def _users_retrieve(self):
    body = self.call('identity_get_users', path_params={'id': self.member.pk})
    self.assertEqual(body['id'], self.member.pk)


def _users_update(self):
    body = self.call(
        'identity_replace_users',
        path_params={'id': self.member.pk},
        body={'first_name': 'Graceful'},
    )
    self.assertEqual(body['first_name'], 'Graceful')


def _users_destroy(self):
    self.call('identity_delete_users', path_params={'id': self.member.pk})
    self.assertFalse(self.company.members.filter(pk=self.member.pk).exists())


def _users_audience(self):
    body = self.call('identity_get_users_audience')
    self.assertGreaterEqual(body.get('count', 0), 1)


def _groups_list(self):
    body = self.call('identity_list_groups')
    self.assertIn('Ops', json.dumps(body))


def _groups_create(self):
    body = self.call('identity_create_groups', body={'display_name': 'New group'})
    self.assertEqual(body['display_name'], 'New group')


def _groups_retrieve(self):
    body = self.call('identity_get_groups', path_params={'id': self.group.pk})
    self.assertEqual(body['display_name'], 'Ops')


def _groups_update(self):
    body = self.call(
        'identity_replace_groups',
        path_params={'id': self.group.pk},
        body={'display_name': 'Renamed'},
    )
    self.assertEqual(body['display_name'], 'Renamed')


def _groups_partial_update(self):
    body = self.call(
        'identity_update_groups',
        path_params={'id': self.group.pk},
        body={'display_name': 'Patched'},
    )
    self.assertEqual(body['display_name'], 'Patched')


def _groups_destroy(self):
    self.call('identity_delete_groups', path_params={'id': self.group.pk})
    self.assertFalse(CompanyGroup.objects.filter(pk=self.group.pk).exists())


def _oauth_clients_list(self):
    body = self.call('identity_list_oauth_clients')
    self.assertIn(str(self.mapping.pk), json.dumps(body))


def _oauth_clients_create(self):
    app = self._social_app('gitlab', 'cid-gitlab')
    body = self.call('identity_create_oauth_clients', body={'social_app_id': app.pk, 'is_active': True})
    self.assertEqual(body['social_app_id'], app.pk)


def _oauth_clients_retrieve(self):
    body = self.call('identity_get_oauth_clients', path_params={'id': self.mapping.pk})
    self.assertEqual(body['id'], self.mapping.pk)


def _oauth_clients_update(self):
    body = self.call(
        'identity_replace_oauth_clients',
        path_params={'id': self.mapping.pk},
        body={'is_active': True},
    )
    self.assertTrue(body['is_active'])


def _oauth_clients_destroy(self):
    self.call('identity_delete_oauth_clients', path_params={'id': self.mapping.pk})
    self.assertFalse(CompanyOAuthClient.objects.filter(pk=self.mapping.pk).exists())


def _oauth_redirects_list(self):
    body = self.call('identity_list_oauth_redirects')
    self.assertIn('https://manual.example.com', json.dumps(body))


def _oauth_redirects_create(self):
    body = self.call(
        'identity_create_oauth_redirects',
        body={'base_url': 'https://new.example.com', 'label': 'New'},
    )
    self.assertEqual(body['base_url'], 'https://new.example.com')


def _oauth_redirects_retrieve(self):
    body = self.call('identity_get_oauth_redirects', path_params={'id': self.redirect.pk})
    self.assertEqual(body['id'], self.redirect.pk)


def _oauth_redirects_partial_update(self):
    body = self.call(
        'identity_update_oauth_redirects',
        path_params={'id': self.redirect.pk},
        body={'label': 'Updated'},
    )
    self.assertEqual(body['label'], 'Updated')


def _oauth_redirects_destroy(self):
    self.call('identity_delete_oauth_redirects', path_params={'id': self.redirect.pk})
    self.assertFalse(CompanyOAuthRedirect.objects.filter(pk=self.redirect.pk).exists())


def _oauth_social_apps_list(self):
    body = self.call('identity_list_oauth_social_apps')
    self.assertIn('github', json.dumps(body))


def _oauth_social_apps_create(self):
    body = self.call(
        'identity_create_oauth_social_apps',
        body={'docs_slug': 'gitlab', 'client_id': 'cid-new', 'client_secret': 'super-secret'},
    )
    self.assertEqual(body['social_app']['provider'], 'gitlab')
    logged = McpCallLog.objects.filter(tool='identity_create_oauth_social_apps').get()
    self.assertEqual(logged.arguments_redacted['body']['client_secret'], '[redacted]')
    self.assertNotIn('super-secret', json.dumps(logged.arguments_redacted))


def _oauth_social_apps_update(self):
    body = self.call(
        'identity_replace_oauth_social_apps',
        path_params={'id': self.social_app.pk},
        body={'client_id': 'cid-github-2'},
    )
    self.assertEqual(body['client_id'], 'cid-github-2')


def _oauth_social_apps_destroy(self):
    self.call('identity_delete_oauth_social_apps', path_params={'id': self.social_app.pk})
    self.assertFalse(SocialApp.objects.filter(pk=self.social_app.pk).exists())


def _oauth_provider_catalog(self):
    body = self.call('identity_get_oauth_provider_catalog')
    self.assertIn('github', json.dumps(body))


def _hosting_update(self):
    body = self.call(
        'identity_replace_hosting_oauth_redirects',
        body={'base_url': 'https://host.example.com', 'label': 'Host'},
    )
    self.assertEqual(body['base_url'], 'https://host.example.com')
    self.assertEqual(body['source'], 'hosting')


def _hosting_destroy(self):
    self.call(
        'identity_delete_hosting_oauth_redirects',
        body={'base_url': 'https://preview.example.com'},
    )
    self.assertFalse(
        CompanyOAuthRedirect.objects.filter(
            company=self.company,
            base_url='https://preview.example.com',
        ).exists()
    )


def _auth_methods_retrieve(self):
    body = self.call('identity_get_auth_methods')
    self.assertTrue(body['enable_magic_link'])


def _auth_methods_partial_update(self):
    body = self.call('identity_update_auth_methods', body={'enable_magic_link': False})
    self.assertFalse(body['enable_magic_link'])


def _auth_methods_update(self):
    body = self.call('identity_replace_auth_methods', body={'enable_magic_link': True})
    self.assertTrue(body['enable_magic_link'])


def _scim_status(self):
    body = self.call('identity_get_scim_status')
    self.assertIn('scim', json.dumps(body).lower())


def _scim_tokens_list(self):
    body = self.call('identity_list_scim_tokens')
    self.assertIn('scimprefix', json.dumps(body))


def _scim_tokens_create(self):
    body = self.call('identity_create_scim_tokens', body={'name': 'minted'})
    self.assertEqual(body.get('token'), '[redacted]')
    self.assertEqual(body.get('name'), 'minted')
    self.assertTrue(CompanyScimToken.objects.filter(company=self.company, name='minted', revoked_at__isnull=True).exists())


def _scim_tokens_revoke(self):
    self.call('identity_revoke_scim_tokens', path_params={'token_id': self.scim.pk})
    self.scim.refresh_from_db()
    self.assertIsNotNone(self.scim.revoked_at)


def _pat_list(self):
    body = self.call('identity_list_personal_access_tokens')
    self.assertIn(str(self.pat.pk), json.dumps(body))


def _pat_create(self):
    body = self.call('identity_create_personal_access_tokens', body={'name': 'minted', 'read_only': True})
    self.assertEqual(body.get('access_token'), '[redacted]')
    self.assertTrue(body['read_only'])
    self.assertEqual(body['name'], 'minted')
    self.assertTrue(
        PersonalAccessToken.objects.filter(company=self.company, user=self.owner, name='minted').exists()
    )


def _pat_revoke(self):
    self.call('identity_revoke_personal_access_tokens', path_params={'key_id': self.pat.pk})
    self.pat.refresh_from_db()
    self.assertIsNotNone(self.pat.revoked_at)


def _companies_list(self):
    body = self.call('identity_list_companies')
    self.assertIn('Tool Co', json.dumps(body))


def _companies_retrieve(self):
    body = self.call('identity_get_companies', path_params={'id': self.company.pk})
    self.assertEqual(body['id'], self.company.pk)


def _companies_update(self):
    body = self.call(
        'identity_replace_companies',
        path_params={'id': self.company.pk},
        body={'name': 'Tool Co Renamed'},
    )
    self.assertEqual(body['name'], 'Tool Co Renamed')


def _companies_partial_update(self):
    body = self.call(
        'identity_update_companies',
        path_params={'id': self.company.pk},
        body={'name': 'Tool Co Patched'},
    )
    self.assertEqual(body['name'], 'Tool Co Patched')


def _invitations_list(self):
    body = self.call('identity_list_invitations')
    self.assertIn('pending@tool.test', json.dumps(body))


def _invitations_create(self):
    body = self.call(
        'identity_create_invitations',
        body={'email': 'new@tool.test', 'language': 'en'},
    )
    self.assertEqual(body['invitation']['email'], 'new@tool.test')


def _invitations_revoke(self):
    body = self.call('identity_revoke_invitations', path_params={'id': self.pending_invite.pk})
    self.assertEqual(body['invitation']['status'], 'revoked')


def _invitations_destroy(self):
    self.call('identity_delete_invitations', path_params={'id': self.revoked_invite.pk})
    self.assertFalse(CompanyInvitation.objects.filter(pk=self.revoked_invite.pk).exists())


def _events_list(self):
    body = self.call('identity_list_events')
    self.assertGreaterEqual(body.get('count', 0), 1)


def _events_retrieve(self):
    body = self.call('identity_get_events', path_params={'id': self.event.pk})
    self.assertEqual(body['id'], self.event.pk)


def _events_types(self):
    body = self.call('identity_list_events_types')
    self.assertTrue(body)


def _events_retention(self):
    body = self.call('identity_get_events_retention')
    self.assertIn('retention', json.dumps(body).lower())


def _actions_events(self):
    body = self.call('identity_list_action_events')
    self.assertIn('identity.user.created', json.dumps(body))


def _actions_rules_list(self):
    body = self.call('identity_list_action_rules')
    row = next(item for item in body['results'] if item['name'] == 'Hook')
    self.assertIs(row['config']['has_secret'], True)
    self.assertNotIn('whsec_test_secret', json.dumps(body))


def _actions_rules_create(self):
    body = self.call(
        'identity_create_action_rules',
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
    body = self.call('identity_get_action_rules', path_params={'id': self.rule.pk})
    self.assertEqual(body['name'], 'Hook')
    self.assertIs(body['config']['has_secret'], True)
    self.assertNotIn('secret', body)


def _actions_rules_partial_update(self):
    body = self.call(
        'identity_update_action_rules',
        path_params={'id': self.rule.pk},
        body={'name': 'Hook renamed'},
    )
    self.assertEqual(body['name'], 'Hook renamed')


def _actions_rules_destroy(self):
    self.call('identity_delete_action_rules', path_params={'id': self.rule.pk})
    self.assertFalse(ActionRule.objects.filter(pk=self.rule.pk).exists())


def _actions_rules_rotate_secret(self):
    body = self.call('identity_rotate_rule_secret', path_params={'id': self.rule.pk})
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
        body = self.call('identity_send_test_rule', path_params={'id': self.rule.pk})
    self.assertTrue(body.get('ok'))


def _actions_deliveries_list(self):
    body = self.call('identity_list_action_deliveries')
    self.assertGreaterEqual(body.get('count', 0), 1)


def _actions_deliveries_retrieve(self):
    body = self.call('identity_get_action_deliveries', path_params={'delivery_id': self.delivery.pk})
    self.assertEqual(body['id'], str(self.delivery.pk))


def _actions_deliveries_requeue(self):
    body = self.call('identity_requeue_action_deliveries', path_params={'delivery_id': self.delivery.pk})
    self.assertEqual(body['status'], 'pending')


def _services_list(self):
    body = self.call('identity_list_services')
    by_id = {item['id']: item['mcp_url'] for item in body['services']}
    self.assertEqual(by_id['identity'], 'https://identity.test/mcp')
    self.assertEqual(by_id['ai'], f'https://ai.test/c/{self.company.pk}/mcp')


TOOL_CALLS = {
    'identity_list_action_deliveries': _actions_deliveries_list,
    'identity_requeue_action_deliveries': _actions_deliveries_requeue,
    'identity_get_action_deliveries': _actions_deliveries_retrieve,
    'identity_list_action_events': _actions_events,
    'identity_create_action_rules': _actions_rules_create,
    'identity_delete_action_rules': _actions_rules_destroy,
    'identity_list_action_rules': _actions_rules_list,
    'identity_update_action_rules': _actions_rules_partial_update,
    'identity_get_action_rules': _actions_rules_retrieve,
    'identity_rotate_rule_secret': _actions_rules_rotate_secret,
    'identity_send_test_rule': _actions_rules_send_test,
    'identity_update_auth_methods': _auth_methods_partial_update,
    'identity_get_auth_methods': _auth_methods_retrieve,
    'identity_replace_auth_methods': _auth_methods_update,
    'identity_list_companies': _companies_list,
    'identity_update_companies': _companies_partial_update,
    'identity_get_companies': _companies_retrieve,
    'identity_replace_companies': _companies_update,
    'identity_list_events': _events_list,
    'identity_get_events_retention': _events_retention,
    'identity_get_events': _events_retrieve,
    'identity_list_events_types': _events_types,
    'identity_create_groups': _groups_create,
    'identity_delete_groups': _groups_destroy,
    'identity_list_groups': _groups_list,
    'identity_update_groups': _groups_partial_update,
    'identity_get_groups': _groups_retrieve,
    'identity_replace_groups': _groups_update,
    'identity_delete_hosting_oauth_redirects': _hosting_destroy,
    'identity_replace_hosting_oauth_redirects': _hosting_update,
    'identity_create_invitations': _invitations_create,
    'identity_delete_invitations': _invitations_destroy,
    'identity_list_invitations': _invitations_list,
    'identity_revoke_invitations': _invitations_revoke,
    'identity_list_services': _services_list,
    'identity_create_oauth_clients': _oauth_clients_create,
    'identity_delete_oauth_clients': _oauth_clients_destroy,
    'identity_list_oauth_clients': _oauth_clients_list,
    'identity_get_oauth_clients': _oauth_clients_retrieve,
    'identity_replace_oauth_clients': _oauth_clients_update,
    'identity_get_oauth_provider_catalog': _oauth_provider_catalog,
    'identity_create_oauth_redirects': _oauth_redirects_create,
    'identity_delete_oauth_redirects': _oauth_redirects_destroy,
    'identity_list_oauth_redirects': _oauth_redirects_list,
    'identity_update_oauth_redirects': _oauth_redirects_partial_update,
    'identity_get_oauth_redirects': _oauth_redirects_retrieve,
    'identity_create_oauth_social_apps': _oauth_social_apps_create,
    'identity_delete_oauth_social_apps': _oauth_social_apps_destroy,
    'identity_list_oauth_social_apps': _oauth_social_apps_list,
    'identity_replace_oauth_social_apps': _oauth_social_apps_update,
    'identity_create_personal_access_tokens': _pat_create,
    'identity_list_personal_access_tokens': _pat_list,
    'identity_revoke_personal_access_tokens': _pat_revoke,
    'identity_get_scim_status': _scim_status,
    'identity_create_scim_tokens': _scim_tokens_create,
    'identity_list_scim_tokens': _scim_tokens_list,
    'identity_revoke_scim_tokens': _scim_tokens_revoke,
    'identity_get_users_audience': _users_audience,
    'identity_delete_users': _users_destroy,
    'identity_list_users': _users_list,
    'identity_get_users': _users_retrieve,
    'identity_replace_users': _users_update,
}


def test_every_exposed_tool_has_a_call_test(self):
    self.assertEqual(set(TOOL_CALLS), set(self.tools))


def test_read_only_agent_cannot_write(self):
    self.agent.access_mode = Agent.ACCESS_READ_ONLY
    self.agent.save(update_fields=['access_mode'])
    self.token = encode_access_token(self.agent, resource=IDENTITY_MCP)
    payload = self._post(
        'identity_create_groups',
        self._arguments('identity_create_groups', body={'display_name': 'Blocked'}),
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
        'identity_get_users',
        self._arguments('identity_get_users', path_params={'id': stranger.pk}),
    )
    self.assertTrue(payload['result'].get('isError'))
    self.assertNotIn('stranger@other.test', payload['result']['content'][0]['text'])


def test_ask_mode_write_runs_after_approval(self):
    self.agent.access_mode = Agent.ACCESS_ASK
    self.agent.save(update_fields=['access_mode'])
    self.token = encode_access_token(self.agent, resource=IDENTITY_MCP)
    arguments = self._arguments('identity_create_groups', body={'display_name': 'Asked'})
    first = self._post('identity_create_groups', arguments)
    self.assertTrue(self._needs_approval(first), first)
    McpApprovalRequest.objects.filter(pk=first['result']['meta']['approval_id']).update(
        status=McpApprovalRequest.STATUS_APPROVED,
    )
    second = self._post('identity_create_groups', arguments)
    self.assertFalse(second['result'].get('isError'), second)
    self.assertTrue(CompanyGroup.objects.filter(company=self.company, display_name='Asked').exists())


def test_safe_read_masks_email(self):
    self.agent.read_level = Agent.READ_SAFE
    self.agent.save(update_fields=['read_level'])
    self.token = encode_access_token(self.agent, resource=IDENTITY_MCP)
    body = self.call('identity_list_users')
    dumped = json.dumps(body)
    self.assertNotIn('owner@tool.test', dumped)
    self.assertIn('[redacted]', dumped)


_bind_tool_tests()
McpToolCallTests.test_every_exposed_tool_has_a_call_test = test_every_exposed_tool_has_a_call_test
McpToolCallTests.test_read_only_agent_cannot_write = test_read_only_agent_cannot_write
McpToolCallTests.test_other_company_user_is_hidden = test_other_company_user_is_hidden
McpToolCallTests.test_ask_mode_write_runs_after_approval = test_ask_mode_write_runs_after_approval
McpToolCallTests.test_safe_read_masks_email = test_safe_read_masks_email
