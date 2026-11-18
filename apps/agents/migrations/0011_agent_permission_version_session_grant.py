"""Agent permission_version and session grant binding for gateway cache invalidation."""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0010_global_mcp_approvals'),
    ]

    operations = [
        migrations.AddField(
            model_name='agent',
            name='permission_version',
            field=models.PositiveIntegerField(
                default=0,
                help_text='Increments when company-scoped permissions change; gates session Allow grants.',
            ),
        ),
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='agent_permission_version',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='global_company_id',
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='company_binding_version',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]
