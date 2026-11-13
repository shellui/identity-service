# Snapshot services and setup context on session grants for session-check authority.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0017_agent_refresh_session_authority_snapshot'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='services_allowed',
            field=models.JSONField(default=list),
        ),
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='setup_company_id',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='setup_context_expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='setup_new_company_grant',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='setup_mcp_session_ttl_seconds',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]
