from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.actions.retention import purge_expired_data
from apps.agents.models import Agent, McpCallLog
from apps.companies.models import Company

User = get_user_model()


class McpAgentRetentionPurgeTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-mcp-ret', data_retention_days=7)
        self.owner = User.objects.create_user(username='owner-ret', email='owner@acme.test', password='x')
        self.cutoff = timezone.now() - timedelta(days=8)

    def _revoked_agent(self, *, name='Revoked', revoked_days_ago=8):
        agent = Agent.objects.create(company=self.company, name=name, created_by=self.owner)
        agent.revoked_at = timezone.now() - timedelta(days=revoked_days_ago)
        agent.save(update_fields=['revoked_at'])
        return agent

    def _call_log(self, agent, *, days_ago=30):
        row = McpCallLog.objects.create(
            agent=agent,
            company=self.company,
            service='identity',
            tool='ping',
        )
        McpCallLog.objects.filter(pk=row.pk).update(created_at=timezone.now() - timedelta(days=days_ago))
        return row

    def test_purge_removes_revoked_agents_past_retention_and_their_logs(self):
        expired = self._revoked_agent(revoked_days_ago=8)
        log = self._call_log(expired, days_ago=30)
        kept = Agent.objects.create(company=self.company, name='Active', created_by=self.owner)
        active_log = self._call_log(kept, days_ago=30)
        recent_revoke = self._revoked_agent(name='Recent revoke', revoked_days_ago=2)
        recent_log = self._call_log(recent_revoke, days_ago=30)

        stats = purge_expired_data(now=timezone.now())

        self.assertEqual(stats['revoked_mcp_agents'], 1)
        self.assertEqual(stats['mcp_call_logs'], 1)
        self.assertFalse(Agent.objects.filter(pk=expired.pk).exists())
        self.assertFalse(McpCallLog.objects.filter(pk=log.pk).exists())
        self.assertTrue(Agent.objects.filter(pk=kept.pk).exists())
        self.assertTrue(McpCallLog.objects.filter(pk=active_log.pk).exists())
        self.assertTrue(Agent.objects.filter(pk=recent_revoke.pk).exists())
        self.assertTrue(McpCallLog.objects.filter(pk=recent_log.pk).exists())

    def test_dry_run_counts_revoked_agents_without_deleting(self):
        expired = self._revoked_agent(revoked_days_ago=10)
        self._call_log(expired, days_ago=5)

        stats = purge_expired_data(dry_run=True, now=timezone.now())

        self.assertEqual(stats['revoked_mcp_agents'], 1)
        self.assertEqual(stats['mcp_call_logs'], 1)
        self.assertTrue(Agent.objects.filter(pk=expired.pk).exists())
        self.assertEqual(McpCallLog.objects.filter(agent=expired).count(), 1)
