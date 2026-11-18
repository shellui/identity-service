"""Stored identity MCP tool names move from api_v1_* operation ids."""

from __future__ import annotations

import importlib
from datetime import timedelta

from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.agents.models import Agent, McpApprovalRequest, McpCallLog
from apps.companies.models import Company

_migration = importlib.import_module('apps.agents.migrations.0025_rename_identity_mcp_tool_names')
User = get_user_model()


class RenameIdentityMcpToolNamesTests(TestCase):
    def test_rewrites_call_logs_and_approvals_and_leaves_other_tools(self):
        company = Company.objects.create(name='Rename Co', slug='rename-co')
        owner = User.objects.create_user(username='rename-owner', password='x')
        agent = Agent.objects.create(company=company, name='Agent', created_by=owner, services_allowed=['identity'])
        log = McpCallLog.objects.create(
            agent=agent,
            company=company,
            service='identity',
            tool='api_v1_groups_create',
            operation_title='api_v1_groups_create',
            resource_label='api_v1_groups_create',
        )
        other = McpCallLog.objects.create(
            agent=agent,
            company=company,
            service='storage',
            tool='write_file',
            operation_title='write_file',
        )
        approval = McpApprovalRequest.objects.create(
            agent=agent,
            company=company,
            service='identity',
            action='api_v1_users_destroy',
            arguments_hash='a' * 64,
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        _migration.rename_identity_tool_names(django_apps, None)

        log.refresh_from_db()
        other.refresh_from_db()
        approval.refresh_from_db()
        self.assertEqual(log.tool, 'identity_create_groups')
        self.assertEqual(log.operation_title, 'identity_create_groups')
        self.assertEqual(log.resource_label, 'identity_create_groups')
        self.assertEqual(other.tool, 'write_file')
        self.assertEqual(approval.action, 'identity_delete_users')
