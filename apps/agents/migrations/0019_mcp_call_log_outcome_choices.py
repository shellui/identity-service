"""Align McpCallLog.outcome CharField choices with canonical MCP audit outcomes."""

from django.db import migrations, models


OUTCOME_CHOICES = [
    ('allowed', 'Allowed'),
    ('failed', 'Failed'),
    ('denied', 'Denied'),
    ('pending_approval', 'Pending approval'),
    ('session_used', 'Session used'),
    ('success', 'Success (legacy)'),
    ('error', 'Error (legacy)'),
]


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0018_mcp_approval_session_grant_snapshots'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mcpcalllog',
            name='outcome',
            field=models.CharField(blank=True, choices=OUTCOME_CHOICES, default='', max_length=32),
        ),
    ]
