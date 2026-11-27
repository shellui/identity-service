"""Global agents carry no owner claims, the revocation snapshot carries each creator's live
standing, and agents cannot change who owns a company."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta

from django.contrib.admin.sites import site as admin_site
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.agents.models import Agent, McpApprovalRequest
from apps.agents.personal_agent_tokens import create_personal_agent_credential
from apps.agents.revocation import blocked_agent_ids, regional_agent_snapshots
from apps.agents.tokens import build_agent_access_token, encode_access_token
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyMembership

User = get_user_model()

SETTINGS = dict(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AI_SERVICE_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
)
IDENTITY_MCP = 'https://identity.test/mcp'


def _rpc(method: str, **params) -> str:
    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})


@override_settings(**SETTINGS)
class GlobalAgentCarriesNoOwnerClaimsTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-global-claims')
        self.user = User.objects.create_user(username='ada', email='ada@g.test', password='x')
        set_company_access(self.company, self.user, enabled=True)
        self.company.owners.add(self.user)
        self.resource = f'https://ai.test/c/{self.company.id}/mcp'

    def test_global_agent_has_neither_claim(self):
        agent = Agent.objects.create(
            company=self.company,
            name='Global',
            created_by=self.user,
            global_agent_id=uuid.uuid4(),
            services_allowed=['ai', 'identity'],
        )
        claims = build_agent_access_token(agent, resource=self.resource)
        self.assertNotIn('owner_user_id', claims)
        self.assertNotIn('owner_is_company_owner', claims)
        self.assertEqual(claims['global_agent_id'], str(agent.global_agent_id))

    def test_regional_agent_still_has_the_owner_id_and_no_role_claim(self):
        agent = Agent.objects.create(
            company=self.company,
            name='Regional',
            created_by=self.user,
            services_allowed=['ai', 'identity'],
        )
        claims = build_agent_access_token(agent, resource=self.resource)
        self.assertEqual(claims['owner_user_id'], self.user.pk)
        # The role is never a token claim. Services read it live from the revocation snapshot.
        self.assertNotIn('owner_is_company_owner', claims)


@override_settings(**SETTINGS)
class CreatorStatusSnapshotTests(TestCase):
    """The signed revocation snapshot carries each agent creator's live standing."""

    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-creator-status')
        self.other = Company.objects.create(name='Other', slug='other-creator-status')
        self.alice = User.objects.create_user(username='alice', email='alice@cs.test', password='x')
        self.bob = User.objects.create_user(username='bob', email='bob@cs.test', password='x')
        for user in (self.alice, self.bob):
            set_company_access(self.company, user, enabled=True)
        self.company.owners.add(self.alice)

    def _personal(self, user, company=None) -> Agent:
        row, _access = create_personal_agent_credential(
            user=user,
            company=company or self.company,
            name=f'{user.username}-token',
            services=['ai', 'storage'],
            access_mode=Agent.ACCESS_FULL,
            read_level=Agent.READ_SAFE,
            allow_destructive=False,
            expires_at=timezone.now() + timedelta(days=90),
        )
        return row.agent

    def _row(self, agent):
        rows = {r['agent_id']: r for r in regional_agent_snapshots(company_id=agent.company_id)}
        return rows[str(agent.pk)]

    def _blocked(self, agent) -> bool:
        return str(agent.pk) in blocked_agent_ids(company_id=agent.company_id)

    def test_member_and_owner_are_reported(self):
        owner_token, member_token = self._personal(self.alice), self._personal(self.bob)
        self.assertEqual(self._row(owner_token)['creator_status'], 'owner')
        self.assertEqual(self._row(member_token)['creator_status'], 'member')
        self.assertFalse(self._blocked(owner_token))
        self.assertFalse(self._blocked(member_token))

    def test_role_changes_show_up_without_a_new_token(self):
        token = self._personal(self.bob)
        self.company.owners.add(self.bob)
        self.assertEqual(self._row(token)['creator_status'], 'owner')
        self.company.owners.remove(self.bob)
        self.assertEqual(self._row(token)['creator_status'], 'member')
        self.company.owners.set([self.bob])
        self.assertEqual(self._row(token)['creator_status'], 'owner')
        self.company.owners.clear()
        self.assertEqual(self._row(token)['creator_status'], 'member')

    def test_removed_creator_is_gone_and_the_agent_is_blocked(self):
        token = self._personal(self.bob)
        CompanyMembership.objects.filter(company=self.company, user=self.bob).delete()
        self.assertEqual(self._row(token)['creator_status'], 'gone')
        self.assertTrue(self._blocked(token))

    def test_disabled_creator_and_inactive_account_are_gone(self):
        token = self._personal(self.bob)
        set_company_access(self.company, self.bob, enabled=False)
        self.assertEqual(self._row(token)['creator_status'], 'gone')
        self.assertTrue(self._blocked(token))
        set_company_access(self.company, self.bob, enabled=True)
        self.assertFalse(self._blocked(token))
        User.objects.filter(pk=self.bob.pk).update(is_active=False)
        self.assertEqual(self._row(token)['creator_status'], 'gone')
        self.assertTrue(self._blocked(token))

    def test_an_owner_who_lost_access_is_gone_not_owner(self):
        token = self._personal(self.alice)
        CompanyMembership.objects.filter(company=self.company, user=self.alice).delete()
        self.assertEqual(self._row(token)['creator_status'], 'gone')
        self.assertTrue(self._blocked(token))

    def test_status_is_per_company(self):
        set_company_access(self.other, self.bob, enabled=True)
        elsewhere = self._personal(self.bob, self.other)
        here = self._personal(self.bob)
        self.other.owners.add(self.bob)
        self.assertEqual(self._row(elsewhere)['creator_status'], 'owner')
        self.assertEqual(self._row(here)['creator_status'], 'member')

    def test_global_agents_and_creatorless_agents_carry_no_status(self):
        global_agent = Agent.objects.create(
            company=self.company, name='G', created_by=self.alice, global_agent_id=uuid.uuid4(),
            services_allowed=['ai'], global_company_id=uuid.uuid4(), company_binding_version=1, grant_version=1,
        )
        service = Agent.objects.create(company=self.company, name='S', services_allowed=['ai'])
        self.assertNotIn('creator_status', self._row(global_agent))
        self.assertNotIn('creator_status', self._row(service))
        # Even when the creator has left, a global agent is not blocked by this rule.
        CompanyMembership.objects.filter(company=self.company, user=self.alice).delete()
        self.assertFalse(self._blocked(global_agent))

    def test_policy_version_changes_with_the_status(self):
        from apps.agents.revocation_jwt import compute_revocation_policy_version

        token = self._personal(self.bob)

        def version():
            return compute_revocation_policy_version(
                revoked_ids=blocked_agent_ids(company_id=self.company.pk),
                agents=regional_agent_snapshots(company_id=self.company.pk),
                cache_seconds=30,
                max_active_grant_version=0,
            )

        before = version()
        self.company.owners.add(self.bob)
        self.assertNotEqual(before, version())
        self.assertEqual(self._row(token)['creator_status'], 'owner')

    def test_signed_poll_response_carries_the_status(self):
        from unittest import mock

        from apps.agents import internal_views
        from apps.agents.revocation_jwt import sign_revocation_list_response

        token = self._personal(self.bob)
        CompanyMembership.objects.filter(company=self.company, user=self.bob).delete()
        agents = regional_agent_snapshots(company_id=self.company.pk)
        ids = blocked_agent_ids(company_id=self.company.pk)
        with mock.patch('apps.agents.revocation_jwt.sign_rs256', side_effect=lambda claims: claims):
            claims = sign_revocation_list_response(
                revoked_agent_ids=ids, agents=agents, cache_seconds=30, revocation_policy_version=1,
                max_active_grant_version=0,
            )
        self.assertIn(str(token.pk), claims['revoked_agent_ids'])
        row = next(r for r in claims['agents'] if r['agent_id'] == str(token.pk))
        self.assertEqual(row['creator_status'], 'gone')
        self.assertTrue(hasattr(internal_views, 'McpRevocationListView'))

    def test_a_gone_creator_cannot_refresh_the_agent(self):
        from apps.agents.tokens import issue_agent_refresh, refresh_agent_access

        resource = f'https://ai.test/c/{self.company.id}/mcp'
        agent = Agent.objects.create(
            company=self.company, name='OAuth', created_by=self.bob, services_allowed=['ai', 'identity']
        )
        refresh, _session = issue_agent_refresh(agent, resource=resource)
        CompanyMembership.objects.filter(company=self.company, user=self.bob).delete()
        self.assertIsNone(refresh_agent_access(refresh, resource=resource))
        # And the same agent could not mint again later, even if the person comes back.
        set_company_access(self.company, self.bob, enabled=True)
        self.assertIsNone(refresh_agent_access(refresh, resource=resource))


@override_settings(**SETTINGS)
class AgentsCannotChangeCompanyOwnersTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Tool Co', slug='tool-co-agent-owners')
        self.owner = User.objects.create_user(username='own', email='own@t.test', password='x')
        self.member = User.objects.create_user(username='mem', email='mem@t.test', password='x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.member, enabled=True)

    def _agent(self, mode):
        agent = Agent.objects.create(
            company=self.company,
            name='Caller',
            created_by=self.owner,
            access_mode=mode,
            read_level=Agent.READ_SENSITIVE,
            services_allowed=['identity'],
        )
        return agent, encode_access_token(agent, resource=IDENTITY_MCP)

    def _mcp(self, token, name, arguments):
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/call', name=name, arguments=arguments),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()['result']

    def _owners(self):
        return sorted(self.company.owners.values_list('pk', flat=True))

    def _assert_refused(self, result):
        text = json.dumps(result)
        self.assertTrue(result.get('isError'), text)
        self.assertIn('agent_cannot_change_owners', text)
        self.assertEqual(self._owners(), [self.owner.pk])

    def _approve_pending(self, agent):
        McpApprovalRequest.objects.filter(agent=agent).update(status=McpApprovalRequest.STATUS_APPROVED)

    def test_agent_cannot_promote_or_replace_owners_in_either_mode(self):
        for mode in (Agent.ACCESS_FULL, Agent.ACCESS_ASK):
            for tool in ('identity_update_companies', 'identity_replace_companies'):
                for owner_ids in ([self.owner.pk, self.member.pk], [self.member.pk]):
                    with self.subTest(mode=mode, tool=tool, owner_ids=owner_ids):
                        agent, token = self._agent(mode)
                        args = {'id': self.company.pk, 'owner_ids': owner_ids}
                        first = self._mcp(token, tool, args)
                        # Identity asks a person before any company write, in both modes.
                        self.assertEqual((first.get('meta') or {}).get('status'), 'pending', json.dumps(first))
                        self.assertEqual(self._owners(), [self.owner.pk])
                        # Even once a person approves the call, the view refuses it.
                        self._approve_pending(agent)
                        self._assert_refused(self._mcp(token, tool, args))

    def test_an_approved_rename_without_owner_ids_still_works(self):
        agent, token = self._agent(Agent.ACCESS_FULL)
        args = {'id': self.company.pk, 'name': 'Renamed'}
        self.assertEqual((self._mcp(token, 'identity_update_companies', args).get('meta') or {}).get('status'), 'pending')
        self._approve_pending(agent)
        result = self._mcp(token, 'identity_update_companies', args)
        self.assertFalse(result.get('isError'), json.dumps(result))
        self.company.refresh_from_db()
        self.assertEqual(self.company.name, 'Renamed')

    def test_agent_bearer_is_not_accepted_on_the_rest_api(self):
        for mode in (Agent.ACCESS_FULL, Agent.ACCESS_ASK):
            with self.subTest(mode=mode):
                _agent, token = self._agent(mode)
                response = APIClient().patch(
                    f'/api/v1/companies/{self.company.pk}/',
                    data={'owner_ids': [self.owner.pk, self.member.pk]},
                    format='json',
                    HTTP_AUTHORIZATION=f'Bearer {token}',
                )
                self.assertEqual(response.status_code, 401, response.content)
                self.assertEqual(self._owners(), [self.owner.pk])

    def test_a_person_can_still_change_owners(self):
        from apps.authapi.views import _issue_shellui_tokens

        auth = f'Bearer {_issue_shellui_tokens(self.owner, company=self.company)["access_token"]}'
        response = APIClient().patch(
            f'/api/v1/companies/{self.company.pk}/',
            data={'owner_ids': [self.owner.pk, self.member.pk]},
            format='json',
            HTTP_AUTHORIZATION=auth,
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(self._owners(), sorted([self.owner.pk, self.member.pk]))


@override_settings(**SETTINGS)
class AgentsCannotRemoveOrDisableOwnersTests(TestCase):
    """Deleting a co-owner or changing an owner's ``is_active`` changes who owns the company."""

    def setUp(self):
        self.company = Company.objects.create(name='Users Co', slug='users-co-agent-owners')
        self.owner = User.objects.create_user(username='own', email='own@u.test', password='x')
        self.co_owner = User.objects.create_user(username='co', email='co@u.test', password='x')
        self.member = User.objects.create_user(username='mem', email='mem@u.test', password='x')
        for user in (self.owner, self.co_owner, self.member):
            set_company_access(self.company, user, enabled=True)
        self.company.owners.add(self.owner, self.co_owner)

    def _agent(self, mode):
        agent = Agent.objects.create(
            company=self.company,
            name='Caller',
            created_by=self.owner,
            access_mode=mode,
            read_level=Agent.READ_SENSITIVE,
            services_allowed=['identity'],
        )
        return agent, encode_access_token(agent, resource=IDENTITY_MCP)

    def _mcp(self, token, name, arguments):
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/call', name=name, arguments=arguments),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()['result']

    def _approve_pending(self, agent):
        McpApprovalRequest.objects.filter(agent=agent).update(status=McpApprovalRequest.STATUS_APPROVED)

    def _assert_refused(self, result):
        text = json.dumps(result)
        self.assertTrue(result.get('isError'), text)
        self.assertIn('agent_cannot_change_owners', text)
        self.assertEqual(sorted(self.company.owners.values_list('pk', flat=True)), sorted([self.owner.pk, self.co_owner.pk]))
        self.assertTrue(User.objects.filter(pk=self.co_owner.pk).exists())
        self.assertTrue(CompanyMembership.objects.filter(company=self.company, user=self.co_owner, is_enabled=True).exists())

    def _refused_after_approval(self, mode, tool, args):
        agent, token = self._agent(mode)
        first = self._mcp(token, tool, args)
        self.assertEqual((first.get('meta') or {}).get('status'), 'pending', json.dumps(first))
        self._approve_pending(agent)
        self._assert_refused(self._mcp(token, tool, args))

    def test_agent_cannot_delete_a_co_owner_in_either_mode(self):
        for mode in (Agent.ACCESS_FULL, Agent.ACCESS_ASK):
            with self.subTest(mode=mode):
                self._refused_after_approval(mode, 'identity_delete_users', {'id': self.co_owner.pk})

    def test_agent_cannot_disable_or_enable_an_owner_in_either_mode(self):
        for mode in (Agent.ACCESS_FULL, Agent.ACCESS_ASK):
            for active in (False, True):
                with self.subTest(mode=mode, is_active=active):
                    self._refused_after_approval(
                        mode, 'identity_replace_users', {'id': self.co_owner.pk, 'is_active': active}
                    )

    def test_an_owners_other_profile_fields_are_not_refused(self):
        agent, token = self._agent(Agent.ACCESS_FULL)
        args = {'id': self.co_owner.pk, 'first_name': 'Co'}
        self.assertEqual((self._mcp(token, 'identity_replace_users', args).get('meta') or {}).get('status'), 'pending')
        self._approve_pending(agent)
        result = self._mcp(token, 'identity_replace_users', args)
        self.assertFalse(result.get('isError'), json.dumps(result))

    def test_agent_can_still_disable_or_remove_a_plain_member_after_approval(self):
        for tool, args in (
            ('identity_replace_users', {'id': self.member.pk, 'is_active': False}),
            ('identity_delete_users', {'id': self.member.pk}),
        ):
            with self.subTest(tool=tool):
                agent, token = self._agent(Agent.ACCESS_FULL)
                self.assertEqual((self._mcp(token, tool, args).get('meta') or {}).get('status'), 'pending')
                self._approve_pending(agent)
                result = self._mcp(token, tool, args)
                self.assertFalse(result.get('isError'), json.dumps(result))

    def test_a_person_can_still_delete_a_co_owner(self):
        from apps.authapi.views import _issue_shellui_tokens

        auth = f'Bearer {_issue_shellui_tokens(self.owner, company=self.company)["access_token"]}'
        response = APIClient().delete(reverse('shellui-admin-user-detail', args=[self.co_owner.pk]), HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 204, response.content)
        self.assertEqual(sorted(self.company.owners.values_list('pk', flat=True)), [self.owner.pk])


@override_settings(**SETTINGS)
class AgentsCannotMintCredentialsTests(TestCase):
    """SCIM tokens, personal access tokens and webhook signing secrets act as a person or a company."""

    def setUp(self):
        from apps.actions.models import ActionRule

        self.company = Company.objects.create(name='Creds Co', slug='creds-co-agent')
        self.owner = User.objects.create_user(username='cown', email='cown@u.test', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.rule = ActionRule.objects.create(
            company=self.company,
            name='hook',
            event_type='user.created',
            config={'url': 'https://example.com/hook', 'secret': 'original-secret-value'},
            enabled=True,
        )

    def _agent(self, mode):
        agent = Agent.objects.create(
            company=self.company,
            name='Caller',
            created_by=self.owner,
            access_mode=mode,
            read_level=Agent.READ_SENSITIVE,
            services_allowed=['identity'],
        )
        return agent, encode_access_token(agent, resource=IDENTITY_MCP)

    def _mcp(self, token, name, arguments):
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/call', name=name, arguments=arguments),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        if 'error' in body:
            # Refused while checking the arguments, before the gate: shaped like a tool error.
            return {'isError': True, 'content': [{'type': 'text', 'text': body['error']['message']}], 'rpc_error': True}
        return body['result']

    def _call_through_approval(self, mode, tool, args):
        """The agent's call, repeated after a person approved it if it asked."""
        agent, token = self._agent(mode)
        result = self._mcp(token, tool, args)
        if (result.get('meta') or {}).get('status') == 'pending':
            McpApprovalRequest.objects.filter(agent=agent).update(status=McpApprovalRequest.STATUS_APPROVED)
            result = self._mcp(token, tool, args)
        return result

    def _refused(self, result):
        text = json.dumps(result)
        self.assertTrue(result.get('isError'), text)
        self.assertIn('agent_cannot_manage_credentials', text)

    def _assert_nothing_minted(self):
        from apps.authapi.models import PersonalAccessToken
        from apps.scim.models import CompanyScimToken

        self.assertFalse(CompanyScimToken.objects.filter(company=self.company).exists())
        self.assertFalse(PersonalAccessToken.objects.filter(company=self.company).exists())
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.config['secret'], 'original-secret-value')

    def test_agent_cannot_create_or_list_scim_tokens_in_any_mode(self):
        for mode in (Agent.ACCESS_FULL, Agent.ACCESS_ASK):
            for tool, args in (
                ('identity_create_scim_tokens', {'name': 'idp'}),
                ('identity_list_scim_tokens', {}),
            ):
                with self.subTest(mode=mode, tool=tool):
                    self._refused(self._call_through_approval(mode, tool, args))
        self._assert_nothing_minted()

    def test_agent_cannot_create_a_personal_access_token_in_any_mode(self):
        for mode in (Agent.ACCESS_FULL, Agent.ACCESS_ASK):
            with self.subTest(mode=mode):
                self._refused(self._call_through_approval(mode, 'identity_create_personal_access_tokens', {'name': 'x'}))
        self._assert_nothing_minted()

    def test_agent_cannot_rotate_a_webhook_signing_secret_in_any_mode(self):
        for mode in (Agent.ACCESS_FULL, Agent.ACCESS_ASK):
            with self.subTest(mode=mode):
                self._refused(self._call_through_approval(mode, 'identity_rotate_rule_secret', {'id': self.rule.pk}))
        self._assert_nothing_minted()

    def test_the_sign_in_and_credential_tools_on_mcp_are_exactly_the_known_ones(self):
        """A new tool that names a token, key, secret or sign-in setting must be looked at before it ships."""
        from shellui_django.mcp import server as mcp_server

        from apps.agents import mcp_views

        names = {t['name'] for t in mcp_server.tools_from_schema(mcp_views._schema())}
        words = ('token', 'secret', 'key', 'credential', 'redirect', 'social_app', 'oauth', 'auth_method')
        found = {n for n in names if any(w in n for w in words)}
        refused_for_agents = {
            'identity_create_scim_tokens',
            'identity_list_scim_tokens',
            'identity_create_personal_access_tokens',
            'identity_rotate_rule_secret',
            'identity_create_oauth_redirects',
            'identity_update_oauth_redirects',
            'identity_replace_hosting_oauth_redirects',
            'identity_create_oauth_social_apps',
            'identity_replace_oauth_social_apps',
            'identity_create_oauth_clients',
            'identity_replace_oauth_clients',
            'identity_update_auth_methods',
            'identity_replace_auth_methods',
        }
        # Reads and calls that only remove access stay available to agents.
        still_allowed = {
            'identity_revoke_scim_tokens',
            'identity_list_personal_access_tokens',
            'identity_revoke_personal_access_tokens',
            'identity_delete_oauth_redirects',
            'identity_delete_hosting_oauth_redirects',
            'identity_delete_oauth_social_apps',
            'identity_delete_oauth_clients',
            'identity_get_oauth_redirects',
            'identity_list_oauth_redirects',
            'identity_get_oauth_clients',
            'identity_list_oauth_clients',
            'identity_list_oauth_social_apps',
            'identity_get_oauth_provider_catalog',
            'identity_get_auth_methods',
        }
        self.assertEqual(found, refused_for_agents | still_allowed)

    def test_a_person_can_still_manage_credentials(self):
        from apps.authapi.views import _issue_shellui_tokens

        auth = f'Bearer {_issue_shellui_tokens(self.owner, company=self.company)["access_token"]}'
        client = APIClient()
        created = client.post('/api/v1/scim/tokens', {'name': 'idp'}, format='json', HTTP_AUTHORIZATION=auth)
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(client.get('/api/v1/scim/tokens', HTTP_AUTHORIZATION=auth).status_code, 200)
        pat = client.post('/api/v1/personal-access-tokens', {'name': 'x'}, format='json', HTTP_AUTHORIZATION=auth)
        self.assertEqual(pat.status_code, 201, pat.content)
        rotated = client.post(f'/api/v1/actions/rules/{self.rule.pk}/rotate-secret', HTTP_AUTHORIZATION=auth)
        self.assertEqual(rotated.status_code, 200, rotated.content)

    def test_an_agent_can_still_revoke_a_credential(self):
        """Revoking only narrows access, so it stays available."""
        from apps.scim.models import CompanyScimToken

        row = CompanyScimToken.objects.create(company=self.company, token_prefix='scim_ab', token_hash='h' * 64, name='n')
        result = self._call_through_approval(Agent.ACCESS_FULL, 'identity_revoke_scim_tokens', {'token_id': str(row.pk)})
        self.assertFalse(result.get('isError'), json.dumps(result))
        row.refresh_from_db()
        self.assertIsNotNone(row.revoked_at)

    def test_an_agent_bearer_on_the_rest_routes_gets_nothing(self):
        _agent, token = self._agent(Agent.ACCESS_FULL)
        client = APIClient()
        auth = {'HTTP_AUTHORIZATION': f'Bearer {token}'}
        for method, path in (
            ('post', '/api/v1/scim/tokens'),
            ('get', '/api/v1/scim/tokens'),
            ('post', '/api/v1/personal-access-tokens'),
            ('post', f'/api/v1/actions/rules/{self.rule.pk}/rotate-secret'),
        ):
            with self.subTest(path=path, method=method):
                response = getattr(client, method)(path, **auth)
                self.assertIn(response.status_code, (401, 403), response.content)
        self._assert_nothing_minted()


class AgentsCannotChangeSignInTests(AgentsCannotMintCredentialsTests):
    """Where sign-in redirects, which providers a company uses and who a webhook trusts."""

    def setUp(self):
        from allauth.socialaccount.models import SocialApp
        from django.contrib.sites.models import Site

        from apps.companies.models import CompanyOAuthClient, CompanyOAuthRedirect

        super().setUp()
        self.redirect = CompanyOAuthRedirect.objects.create(
            company=self.company, base_url='https://manual.example.com', label='Manual'
        )
        self.hosting_redirect = CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://preview.example.com',
            source=CompanyOAuthRedirect.SOURCE_HOSTING,
        )
        self.app = SocialApp.objects.create(
            provider='github',
            name='github',
            client_id='cid-github',
            secret='secret',
            settings={'catalog_slug': 'github', 'created_by_company_id': self.company.id},
        )
        self.app.sites.add(Site.objects.get_current())
        self.mapping = CompanyOAuthClient.objects.create(company=self.company, social_app=self.app, is_active=False)

    def _state(self):
        from allauth.socialaccount.models import SocialApp

        from apps.actions.models import ActionRule
        from apps.companies.models import CompanyOAuthClient, CompanyOAuthRedirect

        self.company.refresh_from_db()
        return {
            'redirects': sorted(CompanyOAuthRedirect.objects.values_list('base_url', 'label', 'source')),
            'apps': sorted(SocialApp.objects.values_list('client_id', 'secret')),
            'clients': sorted(CompanyOAuthClient.objects.values_list('social_app_id', 'is_active')),
            'desktop': (self.company.desktop_redirect_schemes, self.company.allow_desktop_dev_scheme),
            'magic_link': self.company.enable_magic_link,
            'rules': sorted((r.name, json.dumps(r.config, sort_keys=True)) for r in ActionRule.objects.all()),
        }

    def _probe(self, tool, args):
        """Refused in every mode, even after approval, and nothing changed."""
        for mode in (Agent.ACCESS_FULL, Agent.ACCESS_ASK):
            before = self._state()
            with self.subTest(mode=mode, tool=tool, args=sorted(args)):
                self._refused(self._call_through_approval(mode, tool, args))
                self.assertEqual(self._state(), before)

    def test_agent_cannot_create_update_or_replace_a_redirect(self):
        self._probe('identity_create_oauth_redirects', {'base_url': 'https://evil.example.com', 'label': 'x'})
        self._probe('identity_update_oauth_redirects', {'id': self.redirect.pk, 'base_url': 'https://evil.example.com'})
        self._probe('identity_update_oauth_redirects', {'id': self.redirect.pk, 'label': 'Renamed'})
        self._probe('identity_replace_hosting_oauth_redirects', {'base_url': 'https://evil.example.com', 'label': 'x'})

    def test_agent_cannot_change_the_auth_methods(self):
        for tool in ('identity_update_auth_methods', 'identity_replace_auth_methods'):
            for enable in (False, True):
                self._probe(tool, {'enable_magic_link': enable})

    def test_agent_cannot_reach_the_auth_methods_routes_over_rest(self):
        _agent, token = self._agent(Agent.ACCESS_FULL)
        client = APIClient()
        before = self._state()
        for method in ('patch', 'put'):
            response = getattr(client, method)(
                '/api/v1/auth-methods', {'enable_magic_link': not self.company.enable_magic_link},
                format='json', HTTP_AUTHORIZATION=f'Bearer {token}',
            )
            self.assertIn(response.status_code, (401, 403), response.content)
        self.company.refresh_from_db()
        self.assertEqual(self._state(), before)

    def test_a_person_can_still_change_the_auth_methods(self):
        from apps.authapi.views import _issue_shellui_tokens

        auth = f'Bearer {_issue_shellui_tokens(self.owner, company=self.company)["access_token"]}'
        client = APIClient()
        for method in ('patch', 'put'):
            type(self.company).objects.filter(pk=self.company.pk).update(enable_magic_link=False)
            response = getattr(client, method)(
                '/api/v1/auth-methods', {'enable_magic_link': True}, format='json', HTTP_AUTHORIZATION=auth
            )
            self.assertEqual(response.status_code, 200, response.content)
            self.company.refresh_from_db()
            self.assertTrue(self.company.enable_magic_link)
        self.assertEqual(client.get('/api/v1/auth-methods', HTTP_AUTHORIZATION=auth).status_code, 200)

    def test_agent_cannot_change_the_desktop_redirect_fields_on_update_or_replace(self):
        for tool in ('identity_update_companies', 'identity_replace_companies'):
            self._probe(tool, {'id': self.company.pk, 'desktop_redirect_schemes': ['evil-app']})
            self._probe(tool, {'id': self.company.pk, 'allow_desktop_dev_scheme': True})
            self._probe(
                tool,
                {'id': self.company.pk, 'name': 'Renamed', 'desktop_redirect_schemes': ['evil-app'], 'allow_desktop_dev_scheme': True},
            )

    def test_agent_can_still_update_a_company_without_changing_the_desktop_fields(self):
        self.company.desktop_redirect_schemes = ['kept-app']
        self.company.save(update_fields=['desktop_redirect_schemes'])
        for tool in ('identity_update_companies', 'identity_replace_companies'):
            with self.subTest(tool=tool):
                result = self._call_through_approval(
                    Agent.ACCESS_FULL,
                    tool,
                    {'id': self.company.pk, 'name': f'Renamed {tool}', 'desktop_redirect_schemes': ['kept-app'], 'allow_desktop_dev_scheme': False},
                )
                self.assertFalse(result.get('isError'), json.dumps(result))
        self.company.refresh_from_db()
        self.assertEqual(self.company.desktop_redirect_schemes, ['kept-app'])
        self.assertTrue(self.company.name.startswith('Renamed'))

    def test_agent_cannot_create_replace_or_activate_a_social_app_or_oauth_client(self):
        self._probe('identity_create_oauth_social_apps', {'docs_slug': 'gitlab', 'client_id': 'cid-evil', 'client_secret': 'evil-secret'})
        self._probe('identity_replace_oauth_social_apps', {'id': self.app.pk, 'client_id': 'cid-evil'})
        self._probe('identity_replace_oauth_social_apps', {'id': self.app.pk, 'client_secret': 'evil-secret'})
        self._probe('identity_create_oauth_clients', {'social_app_id': self.app.pk, 'is_active': True})
        self._probe('identity_replace_oauth_clients', {'id': self.mapping.pk, 'is_active': True})

    def test_agent_cannot_set_a_webhook_secret_or_authorization_header(self):
        base = {'name': 'new', 'event_type': 'identity.user.created', 'url': 'https://hooks.example.com/n'}
        self._probe('identity_create_action_rules', {**base, 'secret': 'chosen-secret-value-123'})
        self._probe('identity_create_action_rules', {**base, 'authorization_header': 'Bearer chosen'})
        self._probe('identity_create_action_rules', {**base, 'allow_private_urls': True})
        for extra in (
            {'secret': 'chosen-secret-value-123'},
            {'authorization_header': 'Bearer chosen'},
            {'allow_private_urls': True},
            {'name': 'renamed', 'secret': 'chosen-secret-value-123'},
        ):
            self._probe('identity_update_action_rules', {'id': self.rule.pk, **extra})

    def _refused_url(self, result):
        text = json.dumps(result)
        self.assertTrue(result.get('isError'), text)
        self.assertIn('agent_cannot_change_webhook_url', text)

    def test_agent_cannot_change_the_url_of_an_existing_rule(self):
        for mode in (Agent.ACCESS_FULL, Agent.ACCESS_ASK):
            for extra in (
                {'url': 'https://evil.example.com/steal'},
                {'url': 'https://example.com/hook2'},
                {'name': 'renamed', 'url': 'https://evil.example.com/steal'},
            ):
                before = self._state()
                with self.subTest(mode=mode, extra=sorted(extra)):
                    self._refused_url(
                        self._call_through_approval(mode, 'identity_update_action_rules', {'id': self.rule.pk, **extra})
                    )
                    self.assertEqual(self._state(), before)
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.config['url'], 'https://example.com/hook')
        self.assertEqual(self.rule.config['secret'], 'original-secret-value')

    def test_full_mode_create_waits_for_approval_and_shows_the_url(self):
        from apps.actions.models import ActionRule
        from apps.agents.approval_fallback_views import _arguments_text

        args = {
            'name': 'attacker-hook',
            'event_type': 'identity.user.created',
            'url': 'https://attacker.example/h',
        }
        _agent, token = self._agent(Agent.ACCESS_FULL)
        result = self._mcp(token, 'identity_create_action_rules', args)
        self.assertEqual((result.get('meta') or {}).get('status'), 'pending', json.dumps(result))
        self.assertFalse(ActionRule.objects.filter(name='attacker-hook').exists())
        row = McpApprovalRequest.objects.get(pk=result['meta']['approval_id'])
        self.assertIn('https://attacker.example/h', row.short_action_summary)
        self.assertIn('https://attacker.example/h', _arguments_text(row, {'approval_arguments_empty': 'none'}))

    def test_full_mode_create_runs_after_a_person_approves(self):
        from apps.actions.models import ActionRule

        args = {
            'name': 'approved-hook',
            'event_type': 'identity.user.created',
            'url': 'https://hooks.example.com/approved',
        }
        result = self._call_through_approval(Agent.ACCESS_FULL, 'identity_create_action_rules', args)
        self.assertFalse(result.get('isError'), json.dumps(result))
        rule = ActionRule.objects.get(name='approved-hook')
        self.assertEqual(rule.config['url'], 'https://hooks.example.com/approved')

    def test_agent_can_send_the_same_url_and_can_still_create_a_rule_with_one(self):
        from apps.actions.models import ActionRule

        same = self._call_through_approval(
            Agent.ACCESS_FULL,
            'identity_update_action_rules',
            {'id': self.rule.pk, 'name': 'same-url', 'url': 'https://example.com/hook'},
        )
        self.assertFalse(same.get('isError'), json.dumps(same))
        self.assertEqual(ActionRule.objects.get(pk=self.rule.pk).name, 'same-url')
        created = self._call_through_approval(
            Agent.ACCESS_ASK,
            'identity_create_action_rules',
            {'name': 'with-url', 'event_type': 'identity.user.created', 'url': 'https://hooks.example.com/w'},
        )
        self.assertFalse(created.get('isError'), json.dumps(created))
        self.assertEqual(ActionRule.objects.get(name='with-url').config['url'], 'https://hooks.example.com/w')

    def _refused_with(self, result, code):
        text = json.dumps(result)
        self.assertTrue(result.get('isError'), text)
        self.assertIn(code, text)

    def _probe_webhook_value(self, tool, args, code='agent_webhook_value_refused', *, up_front=True):
        """Refused in every mode. A bad create or update never gets an approval row."""
        for mode in (Agent.ACCESS_FULL, Agent.ACCESS_ASK):
            before = self._state()
            rows = McpApprovalRequest.objects.count()
            with self.subTest(mode=mode, tool=tool, args=sorted(args)):
                result = self._call_through_approval(mode, tool, args)
                self._refused_with(result, code)
                self.assertEqual(self._state(), before)
                if up_front:
                    self.assertTrue(result.get('rpc_error'), json.dumps(result))
                    self.assertEqual(McpApprovalRequest.objects.count(), rows)

    def test_summary_shows_the_event_type_and_host_first_when_the_description_is_padded(self):
        from apps.agents.mcp_views import _approval_summary

        url = 'https://attacker.example/h'
        for arguments in (
            {'body': {'name': 'x', 'event_type': 'identity.user.created', 'description': 'a' * 600, 'url': url}},
            {'description': 'a' * 600, 'name': 'x', 'body': {'event_type': 'identity.user.created', 'url': url}},
        ):
            summary = _approval_summary({'action': 'identity_create_action_rules', 'arguments': arguments})
            self.assertTrue(
                summary.startswith('Create a webhook for identity.user.created that posts to attacker.example: '),
                summary,
            )
            self.assertIn(url, summary)
            self.assertLessEqual(len(summary), 500)

    def test_summary_shows_the_real_host_when_the_url_is_padded_with_userinfo(self):
        from apps.agents.mcp_views import _approval_summary

        padded = 'https://' + 'x' * 520 + '@attacker.example/h'
        summary = _approval_summary({'action': 'identity_create_action_rules', 'arguments': {'body': {'url': padded}}})
        self.assertTrue(summary.startswith('Create a webhook that posts to attacker.example: '), summary)
        self.assertNotIn('x' * 20, summary)
        self.assertIn('https://***@attacker.example/h', summary)
        self.assertLessEqual(len(summary), 500)
        for odd in ('', 'not a url', 'https://', 'https://@', 'https://[::1'):
            self.assertLessEqual(
                len(_approval_summary({'action': 'identity_create_action_rules', 'arguments': {'url': odd}})), 500
            )

    def test_summary_cannot_be_forged_or_disguised_by_the_url(self):
        from apps.agents.mcp_views import _approval_summary

        def summary(url, event_type='identity.user.created'):
            return _approval_summary(
                {'action': 'identity_create_action_rules', 'arguments': {'body': {'url': url, 'event_type': event_type}}}
            )

        forged = summary('https://attacker.example/h\nApproved by admin')
        self.assertNotIn('\n', forged)
        self.assertEqual(forged.count('Create a webhook'), 1)
        hidden = summary('https://attacker.example/h\u202e\u200bgnp.x')
        self.assertTrue(hidden.isascii(), hidden)
        homograph = summary('https://p\u0430ypal.com/h')
        self.assertIn('xn--pypal-4ve.com', homograph)
        self.assertTrue(homograph.isascii(), homograph)
        self.assertNotIn('for ', summary('https://a.example/h', event_type='x\nApproved by admin'))

    def test_full_mode_create_with_a_long_description_shows_the_host_and_event_type_first(self):
        from apps.agents.approval_fallback_views import _arguments_text

        args = {
            'name': 'long-description',
            'event_type': 'identity.user.created',
            'description': 'a' * 500,
            'url': 'https://attacker.example/h',
        }
        _agent, token = self._agent(Agent.ACCESS_FULL)
        result = self._mcp(token, 'identity_create_action_rules', args)
        self.assertEqual((result.get('meta') or {}).get('status'), 'pending', json.dumps(result))
        row = McpApprovalRequest.objects.get(pk=result['meta']['approval_id'])
        self.assertTrue(
            row.short_action_summary.startswith(
                'Create a webhook for identity.user.created that posts to attacker.example: https://attacker.example/h'
            ),
            row.short_action_summary,
        )
        self.assertIn('attacker.example', _arguments_text(row, {'approval_arguments_empty': 'none'})[:200])

    def test_padded_description_or_url_is_refused_before_any_approval_exists(self):
        from apps.actions.models import ActionRule

        base = {'name': 'padded', 'event_type': 'identity.user.created', 'url': 'https://attacker.example/h'}
        self._probe_webhook_value('identity_create_action_rules', {**base, 'description': 'a' * 600})
        self._probe_webhook_value(
            'identity_create_action_rules', {**base, 'url': 'https://' + 'x' * 520 + '@attacker.example/h'}
        )
        self.assertFalse(ActionRule.objects.filter(name='padded').exists())

    def test_lookalike_and_nonprinting_characters_are_refused_before_any_approval_exists(self):
        from apps.actions.models import ActionRule

        base = {'name': 'lookalike', 'event_type': 'identity.user.created', 'url': 'https://hooks.example.com/n'}
        for url in (
            'https://p\u0430ypal.com/h',  # Cyrillic a: shown as paypal.com, delivered to xn--pypal-4ve.com
            'https://p\u0430ypal.com:8443/h',
            'https://hooks.example.com/h\nApproved by admin',
            'https://hooks.example.com/h\r\nApproved by admin',
            'https://hooks.example.com/h\u202egnp.x',  # right-to-left override
            'https://hooks.example.com/h\u200b',  # zero-width space
            'https://hooks.example.com/h\u2060',  # word joiner
            'https://hooks.example.com/h\x00',
        ):
            self._probe_webhook_value('identity_create_action_rules', {**base, 'url': url})
        for description in ('rtl \u202e text', 'zero\u200bwidth', 'nul\x00', 'bell\x07', 'esc\x1b[31m'):
            self._probe_webhook_value('identity_create_action_rules', {**base, 'description': description})
            self._probe_webhook_value(
                'identity_update_action_rules', {'id': self.rule.pk, 'description': description}
            )
        self._probe_webhook_value(
            'identity_update_action_rules', {'id': self.rule.pk, 'url': 'https://p\u0430ypal.com/h'}
        )
        self.assertFalse(ActionRule.objects.filter(name='lookalike').exists())

    def test_agent_can_use_the_ascii_form_of_an_international_host(self):
        from apps.actions.models import ActionRule

        args = {
            'name': 'ascii-form',
            'event_type': 'identity.user.created',
            'url': 'https://xn--pypal-4ve.com/h',
            'description': 'Caf\u00e9 alerts, non-ASCII text is fine outside the host',
        }
        result = self._call_through_approval(Agent.ACCESS_FULL, 'identity_create_action_rules', args)
        self.assertFalse(result.get('isError'), json.dumps(result))
        self.assertTrue(ActionRule.objects.filter(name='ascii-form').exists())

    def test_invalid_webhook_arguments_are_refused_before_any_approval_exists(self):
        base = {'name': 'invalid', 'event_type': 'identity.user.created', 'url': 'https://hooks.example.com/n'}
        for extra in ({'url': 'not a url'}, {'event_type': 'no.such.event'}):
            self._probe_webhook_value(
                'identity_create_action_rules', {**base, **extra}, code='invalid_webhook_arguments'
            )

    def test_a_person_on_rest_is_not_held_to_the_agent_limits(self):
        from apps.actions.models import ActionRule
        from apps.authapi.views import _issue_shellui_tokens

        auth = f'Bearer {_issue_shellui_tokens(self.owner, company=self.company)["access_token"]}'
        response = APIClient().patch(
            f'/api/v1/actions/rules/{self.rule.pk}',
            {'description': 'line one\nline two ' + 'd' * 600},
            format='json',
            HTTP_AUTHORIZATION=auth,
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(ActionRule.objects.get(pk=self.rule.pk).description.startswith('line one'))

    def test_agent_cannot_send_userinfo_or_oversized_webhook_values(self):
        base = {'name': 'new', 'event_type': 'identity.user.created', 'url': 'https://hooks.example.com/n'}
        for extra in (
            {'url': 'https://user:pass@hooks.example.com/n'},
            {'url': 'https://user@hooks.example.com/n'},
            {'description': 'd' * 501},
        ):
            self._probe_webhook_value('identity_create_action_rules', {**base, **extra})
        # Django's URL validator already stops anything over 2048 characters; the agent cap says the same.
        too_long_url = 'https://hooks.example.com/' + 'p' * 2030
        self.assertGreater(len(too_long_url), 2048)
        self._probe_webhook_value('identity_create_action_rules', {**base, 'url': too_long_url})
        for extra in ({'description': 'd' * 501}, {'name': 'renamed', 'description': 'd' * 501}):
            self._probe_webhook_value('identity_update_action_rules', {'id': self.rule.pk, **extra})

    def test_agent_can_send_a_description_at_the_limit(self):
        from apps.actions.models import ActionRule

        args = {
            'name': 'at-the-limit',
            'event_type': 'identity.user.created',
            'description': 'd' * 500,
            'url': 'https://hooks.example.com/limit',
        }
        result = self._call_through_approval(Agent.ACCESS_FULL, 'identity_create_action_rules', args)
        self.assertFalse(result.get('isError'), json.dumps(result))
        self.assertTrue(ActionRule.objects.filter(name='at-the-limit').exists())

    def test_agent_can_use_line_breaks_and_tabs_in_a_description_and_none_reaches_the_summary(self):
        from apps.actions.models import ActionRule

        description = 'First line\nSecond line\r\n\tindented ' + 'x' * 50
        args = {
            'name': 'multi-line',
            'event_type': 'identity.user.created',
            'description': description,
            'url': 'https://hooks.example.com/ml',
        }
        _agent, token = self._agent(Agent.ACCESS_ASK)
        result = self._mcp(token, 'identity_create_action_rules', args)
        self.assertEqual((result.get('meta') or {}).get('status'), 'pending', json.dumps(result))
        row = McpApprovalRequest.objects.get(pk=result['meta']['approval_id'])
        self.assertNotIn('\n', row.short_action_summary)
        self.assertNotIn('\r', row.short_action_summary)
        self.assertNotIn('\t', row.short_action_summary)
        McpApprovalRequest.objects.filter(pk=row.pk).update(status=McpApprovalRequest.STATUS_APPROVED)
        self.assertFalse(self._mcp(token, 'identity_create_action_rules', args).get('isError'))
        self.assertEqual(ActionRule.objects.get(name='multi-line').description, description)

    def test_legacy_envelope_cannot_show_one_destination_and_create_another(self):
        from apps.actions.models import ActionRule

        # Fields under `body` are what the call forwards and creates. Top-level url and event_type are not.
        args = {
            'path': '/api/v1/actions/rules',
            'method': 'POST',
            'url': 'https://good.example/ok',
            'event_type': 'identity.user.updated',
            'body': {
                'name': 'spoof',
                'event_type': 'identity.user.created',
                'url': 'https://attacker.example/hidden',
            },
        }
        _agent, token = self._agent(Agent.ACCESS_ASK)
        result = self._mcp(token, 'identity_create_action_rules', args)
        self.assertEqual((result.get('meta') or {}).get('status'), 'pending', json.dumps(result))
        row = McpApprovalRequest.objects.get(pk=result['meta']['approval_id'])
        self.assertTrue(
            row.short_action_summary.startswith(
                'Create a webhook for identity.user.created that posts to attacker.example: https://attacker.example/hidden'
            ),
            row.short_action_summary,
        )
        self.assertNotIn('good.example', row.short_action_summary)
        self.assertNotIn('identity.user.updated', row.short_action_summary)
        McpApprovalRequest.objects.filter(pk=row.pk).update(status=McpApprovalRequest.STATUS_APPROVED)
        self._mcp(token, 'identity_create_action_rules', args)
        rule = ActionRule.objects.get(name='spoof')
        self.assertEqual(rule.config['url'], 'https://attacker.example/hidden')
        self.assertEqual(rule.event_type, 'identity.user.created')

    def test_summary_ignores_top_level_values_next_to_a_body(self):
        from apps.agents.mcp_views import _approval_summary

        summary = _approval_summary(
            {
                'action': 'identity_create_action_rules',
                'arguments': {
                    'url': 'https://good.example/ok',
                    'event_type': 'identity.user.updated',
                    'body': {'url': 'https://attacker.example/h', 'event_type': 'identity.user.created'},
                },
            }
        )
        self.assertIn('attacker.example', summary)
        self.assertNotIn('good.example', summary)
        self.assertEqual(_approval_summary({'action': 'identity_create_action_rules', 'arguments': {'url': 'https://good.example/ok'}}), 'Create a webhook rule')

    def test_agent_cannot_change_the_event_type_of_an_existing_rule(self):
        self.rule.event_type = 'identity.user.updated'
        self.rule.save(update_fields=['event_type'])
        for extra in (
            {'event_type': 'identity.user.created'},
            {'name': 'renamed', 'event_type': 'identity.user.created'},
        ):
            self._probe_webhook_value(
                'identity_update_action_rules',
                {'id': self.rule.pk, **extra},
                code='agent_cannot_change_webhook_event_type',
                up_front=False,
            )
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.event_type, 'identity.user.updated')

    def test_agent_can_send_the_same_event_type_on_an_update(self):
        from apps.actions.models import ActionRule

        self.rule.event_type = 'identity.user.updated'
        self.rule.save(update_fields=['event_type'])
        result = self._call_through_approval(
            Agent.ACCESS_FULL,
            'identity_update_action_rules',
            {'id': self.rule.pk, 'name': 'same-event', 'event_type': self.rule.event_type},
        )
        self.assertFalse(result.get('isError'), json.dumps(result))
        self.assertEqual(ActionRule.objects.get(pk=self.rule.pk).name, 'same-event')

    def test_a_person_can_still_change_the_event_type_of_a_rule(self):
        from apps.actions.models import ActionRule

        from apps.authapi.views import _issue_shellui_tokens

        auth = f'Bearer {_issue_shellui_tokens(self.owner, company=self.company)["access_token"]}'
        response = APIClient().patch(
            f'/api/v1/actions/rules/{self.rule.pk}',
            {'event_type': 'identity.user.created'},
            format='json',
            HTTP_AUTHORIZATION=auth,
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(ActionRule.objects.get(pk=self.rule.pk).event_type, 'identity.user.created')

    def test_a_person_can_still_change_the_url_of_a_rule(self):
        from apps.actions.models import ActionRule
        from apps.authapi.views import _issue_shellui_tokens

        auth = f'Bearer {_issue_shellui_tokens(self.owner, company=self.company)["access_token"]}'
        response = APIClient().patch(
            f'/api/v1/actions/rules/{self.rule.pk}',
            {'url': 'https://hooks.example.com/moved'},
            format='json',
            HTTP_AUTHORIZATION=auth,
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(ActionRule.objects.get(pk=self.rule.pk).config['url'], 'https://hooks.example.com/moved')

    def test_an_agent_bearer_cannot_patch_a_rule_url_over_rest(self):
        _agent, token = self._agent(Agent.ACCESS_FULL)
        before = self._state()
        response = APIClient().patch(
            f'/api/v1/actions/rules/{self.rule.pk}',
            {'url': 'https://evil.example.com/steal'},
            format='json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertIn(response.status_code, (401, 403), response.content)
        self.assertEqual(self._state(), before)

    def test_agent_can_still_create_and_rename_a_rule_without_those_fields(self):
        from apps.actions.models import ActionRule

        base = {'name': 'plain', 'event_type': 'identity.user.created', 'url': 'https://hooks.example.com/p'}
        created = self._call_through_approval(Agent.ACCESS_FULL, 'identity_create_action_rules', base)
        self.assertFalse(created.get('isError'), json.dumps(created))
        renamed = self._call_through_approval(
            Agent.ACCESS_FULL, 'identity_update_action_rules', {'id': self.rule.pk, 'name': 'renamed', 'allow_private_urls': False}
        )
        self.assertFalse(renamed.get('isError'), json.dumps(renamed))
        self.assertEqual(ActionRule.objects.get(pk=self.rule.pk).name, 'renamed')

    def test_agent_can_still_read_and_remove(self):
        from apps.companies.models import CompanyOAuthClient, CompanyOAuthRedirect

        for tool, args in (
            ('identity_list_oauth_redirects', {}),
            ('identity_get_oauth_redirects', {'id': self.redirect.pk}),
            ('identity_list_oauth_social_apps', {}),
            ('identity_list_oauth_clients', {}),
            ('identity_get_oauth_clients', {'id': self.mapping.pk}),
            ('identity_get_auth_methods', {}),
        ):
            with self.subTest(tool=tool):
                result = self._call_through_approval(Agent.ACCESS_FULL, tool, args)
                self.assertFalse(result.get('isError'), json.dumps(result))
        for tool, args in (
            ('identity_delete_oauth_redirects', {'id': self.redirect.pk}),
            ('identity_delete_hosting_oauth_redirects', {'base_url': 'https://preview.example.com'}),
            ('identity_delete_oauth_clients', {'id': self.mapping.pk}),
        ):
            with self.subTest(tool=tool):
                result = self._call_through_approval(Agent.ACCESS_FULL, tool, args)
                self.assertFalse(result.get('isError'), json.dumps(result))
        self.assertFalse(CompanyOAuthRedirect.objects.filter(pk=self.redirect.pk).exists())
        self.assertFalse(CompanyOAuthRedirect.objects.filter(pk=self.hosting_redirect.pk).exists())
        self.assertFalse(CompanyOAuthClient.objects.filter(pk=self.mapping.pk).exists())

    def test_a_person_can_still_change_sign_in(self):
        from apps.actions.models import ActionRule
        from apps.authapi.views import _issue_shellui_tokens

        auth = f'Bearer {_issue_shellui_tokens(self.owner, company=self.company)["access_token"]}'
        client = APIClient()
        made = client.post('/api/v1/oauth-redirects', {'base_url': 'https://ok.example.com', 'label': 'ok'}, format='json', HTTP_AUTHORIZATION=auth)
        self.assertEqual(made.status_code, 201, made.content)
        patched = client.patch(
            f'/api/v1/companies/{self.company.pk}/',
            {'desktop_redirect_schemes': ['ok-app'], 'allow_desktop_dev_scheme': True},
            format='json',
            HTTP_AUTHORIZATION=auth,
        )
        self.assertEqual(patched.status_code, 200, patched.content)
        self.company.refresh_from_db()
        self.assertEqual(self.company.desktop_redirect_schemes, ['ok-app'])
        rule = client.patch(
            f'/api/v1/actions/rules/{self.rule.pk}',
            {'secret': 'a-person-chose-this-secret', 'authorization_header': 'Bearer person'},
            format='json',
            HTTP_AUTHORIZATION=auth,
        )
        self.assertEqual(rule.status_code, 200, rule.content)
        self.assertEqual(ActionRule.objects.get(pk=self.rule.pk).config['secret'], 'a-person-chose-this-secret')
