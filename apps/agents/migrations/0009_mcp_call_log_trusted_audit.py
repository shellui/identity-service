"""Trusted gateway metadata fields on McpCallLog (ai #24)."""

from __future__ import annotations

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('agents', '0008_mcp_approval_v1'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpcalllog',
            name='operation_title',
            field=models.CharField(blank=True, default='', max_length=200),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='access_kind',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='operation_result',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='resource_label',
            field=models.CharField(blank=True, default='', max_length=120),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='company_name_snapshot',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='approval_request',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='call_logs',
                to='agents.mcpapprovalrequest',
            ),
        ),
    ]
