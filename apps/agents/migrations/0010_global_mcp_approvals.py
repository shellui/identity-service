"""Global account-scope MCP approvals and agent binding metadata."""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0009_agent_setup_context'),
    ]

    operations = [
        migrations.AddField(
            model_name='agent',
            name='global_company_id',
            field=models.UUIDField(
                blank=True,
                help_text='SaaS global company id when bound (token exchange).',
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='agent',
            name='company_binding_version',
            field=models.PositiveIntegerField(
                blank=True,
                help_text='SaaS company binding version last accepted at exchange.',
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='global_agent_id',
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='global_company_id',
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='company_binding_version',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='setup_expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='global_user_sub',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='is_company_owner_actor',
            field=models.BooleanField(
                default=False,
                help_text='Dashboard-only: whether the approving actor is an owner for this global company context.',
            ),
        ),
        migrations.AlterField(
            model_name='mcpapprovalrequest',
            name='agent',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='approval_requests',
                to='agents.agent',
            ),
        ),
        migrations.AlterField(
            model_name='mcpapprovalrequest',
            name='company',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='mcp_approval_requests',
                to='companies.company',
            ),
        ),
    ]
