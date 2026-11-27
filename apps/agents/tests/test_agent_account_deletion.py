"""A deleted account or company must not leave agents working, and an agent check is one row."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.actions.retention import purge_expired_data
from apps.agents.models import Agent, DeletedAgentRevocation, McpApprovalRequest
from apps.agents.personal_agent_tokens import create_personal_agent_credential
from apps.agents.revocation import (
    agent_id_is_blocked,
    blocked_agent_ids,
    is_agent_blocked,
    regional_agent_snapshots,
    revoked_agent_ids,
)
from apps.agents.tokens import encode_access_token, issue_agent_refresh, refresh_agent_access
from apps.authapi.account_lifecycle import delete_user_account
from apps.companies.access import set_company_access
from apps.companies.models import Company

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
class DeletingAnAccountRevokesItsAgentsTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Del Co', slug='del-co-agents')
        self.alice = User.objects.create_user(username='alice', email='alice@d.test', password='x')
        self.bob = User.objects.create_user(username='bob', email='bob@d.test', password='x')
        for user in (self.alice, self.bob):
            set_company_access(self.company, user, enabled=True)
        self.company.owners.add(self.alice)
        self.resource = f'https://ai.test/c/{self.company.id}/mcp'
        row, _access = create_personal_agent_credential(
            user=self.bob,
            company=self.company,
            name='bob-token',
            services=['ai', 'identity'],
            access_mode=Agent.ACCESS_FULL,
            read_level=Agent.READ_SAFE,
            allow_destructive=False,
            expires_at=timezone.now() + timedelta(days=90),
        )
        self.personal = row.agent
        self.oauth = Agent.objects.create(
            company=self.company, name='OAuth', created_by=self.bob, services_allowed=['ai', 'identity']
        )
        self.global_agent = Agent.objects.create(
            company=self.company,
            name='Global',
            created_by=self.bob,
            global_agent_id=uuid.uuid4(),
            services_allowed=['ai'],
            global_company_id=uuid.uuid4(),
            company_binding_version=1,
            grant_version=1,
        )

    def _assert_bobs_agents_are_cut_off(self):
        ids = revoked_agent_ids(company_id=self.company.pk)
        self.assertIn(str(self.personal.pk), ids)
        self.assertIn(str(self.oauth.pk), ids)
        self.assertIn(str(self.personal.pk), blocked_agent_ids(company_id=self.company.pk))
        for agent in (self.personal, self.oauth):
            self.assertTrue(agent_id_is_blocked(str(agent.pk), self.company.pk))
            row = Agent.objects.get(pk=agent.pk)
            self.assertIsNotNone(row.revoked_at)
            self.assertIsNone(row.created_by_id)
        # Identity's own /mcp refuses the personal token.
        token = encode_access_token(Agent.objects.get(pk=self.personal.pk), resource=IDENTITY_MCP)
        response = self.client.post(
            '/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertIn(response.status_code, (401, 403), response.content)
        # And the OAuth agent cannot refresh.
        self.assertIsNone(refresh_agent_access(self._refresh, resource=self.resource))

    def test_delete_user_account_revokes_the_users_agents(self):
        self._refresh, _s = issue_agent_refresh(self.oauth, resource=self.resource)
        self.assertFalse(agent_id_is_blocked(str(self.personal.pk), self.company.pk))
        delete_user_account(self.bob, source='test')
        self.assertFalse(User.objects.filter(pk=self.bob.pk).exists())
        self._assert_bobs_agents_are_cut_off()

    def test_a_django_admin_style_delete_revokes_them_too(self):
        self._refresh, _s = issue_agent_refresh(self.oauth, resource=self.resource)
        self.bob.delete()
        self._assert_bobs_agents_are_cut_off()

    def test_global_agents_are_not_revoked_by_the_users_deletion(self):
        self.bob.delete()
        self.assertIsNone(Agent.objects.get(pk=self.global_agent.pk).revoked_at)
        self.assertNotIn(str(self.global_agent.pk), revoked_agent_ids(company_id=self.company.pk))

    def test_other_users_agents_are_untouched(self):
        mine = Agent.objects.create(company=self.company, name='Alice', created_by=self.alice, services_allowed=['ai'])
        self.bob.delete()
        self.assertFalse(agent_id_is_blocked(str(mine.pk), self.company.pk))


@override_settings(**SETTINGS)
class DeletingACompanyKeepsItsAgentsRevokedTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Gone Co', slug='gone-co-agents')
        self.user = User.objects.create_user(username='carl', email='carl@d.test', password='x')
        set_company_access(self.company, self.user, enabled=True)
        self.agent = Agent.objects.create(
            company=self.company, name='A', created_by=self.user, services_allowed=['ai']
        )
        self.company_id = self.company.pk

    def test_the_agents_stay_in_the_revoked_list_after_the_company_is_deleted(self):
        agent_id = str(self.agent.pk)
        self.assertNotIn(agent_id, revoked_agent_ids(company_id=self.company_id))
        self.company.delete()
        self.assertFalse(Agent.objects.filter(pk=agent_id).exists())
        self.assertIn(agent_id, revoked_agent_ids(company_id=self.company_id))
        self.assertIn(agent_id, revoked_agent_ids())
        self.assertIn(agent_id, blocked_agent_ids(company_id=self.company_id))
        self.assertTrue(agent_id_is_blocked(agent_id, self.company_id))
        self.assertNotIn(agent_id, {r['agent_id'] for r in regional_agent_snapshots(company_id=self.company_id)})

    def test_a_purged_revoked_agent_stays_refused_until_a_personal_token_would_expire(self):
        self.agent.revoked_at = timezone.now() - timedelta(days=30)
        self.agent.save(update_fields=['revoked_at'])
        purge_expired_data(now=timezone.now())
        self.assertFalse(Agent.objects.filter(pk=self.agent.pk).exists())
        self.assertIn(str(self.agent.pk), revoked_agent_ids(company_id=self.company_id))
        # Past the longest token lifetime the tombstone itself is purged.
        DeletedAgentRevocation.objects.filter(pk=self.agent.pk).update(deleted_at=timezone.now() - timedelta(days=200))
        purge_expired_data(now=timezone.now())
        self.assertNotIn(str(self.agent.pk), revoked_agent_ids(company_id=self.company_id))


@override_settings(**SETTINGS)
class AgentCheckLooksAtOneAgentTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='One Co', slug='one-co-agents')
        self.user = User.objects.create_user(username='dee', email='dee@d.test', password='x')
        set_company_access(self.company, self.user, enabled=True)

    def _make(self, n):
        return [
            Agent.objects.create(company=self.company, name=f'A{i}', created_by=self.user, services_allowed=['ai'])
            for i in range(n)
        ]

    def test_cost_does_not_grow_with_the_number_of_agents(self):
        first = self._make(1)[0]
        with self.assertNumQueries(4):
            self.assertFalse(agent_id_is_blocked(str(first.pk), self.company.pk))
        self._make(25)
        with self.assertNumQueries(4):
            self.assertFalse(agent_id_is_blocked(str(first.pk), self.company.pk))
        with self.assertNumQueries(3):
            self.assertFalse(is_agent_blocked(first))

    def test_the_same_rules_as_the_company_wide_list(self):
        agent = self._make(1)[0]
        self.assertFalse(is_agent_blocked(agent))
        agent.paused_at = timezone.now()
        self.assertTrue(is_agent_blocked(agent))
        agent.paused_at = None
        agent.expires_at = timezone.now() - timedelta(seconds=1)
        self.assertTrue(is_agent_blocked(agent))
        agent.expires_at = None
        agent.revoked_at = timezone.now()
        self.assertTrue(is_agent_blocked(agent))
        agent.revoked_at = None
        self.assertFalse(is_agent_blocked(agent))
        set_company_access(self.company, self.user, enabled=False)
        self.assertTrue(is_agent_blocked(agent))

    def test_unknown_malformed_or_other_company_ids_are_blocked(self):
        agent = self._make(1)[0]
        other = Company.objects.create(name='Other', slug='other-one-co')
        self.assertTrue(agent_id_is_blocked(str(uuid.uuid4()), self.company.pk))
        self.assertTrue(agent_id_is_blocked('not-a-uuid', self.company.pk))
        self.assertTrue(agent_id_is_blocked(str(agent.pk), other.pk))
