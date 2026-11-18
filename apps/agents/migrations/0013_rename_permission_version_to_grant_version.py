# Canonical name grant_version (MCP); session grant row agent_grant_version.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0012_mcp_call_log_audit_fields'),
    ]

    operations = [
        migrations.RenameField(
            model_name='agent',
            old_name='permission_version',
            new_name='grant_version',
        ),
        migrations.RenameField(
            model_name='mcpapprovalsessiongrant',
            old_name='agent_permission_version',
            new_name='agent_grant_version',
        ),
    ]
