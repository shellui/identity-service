import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0007_personal_agent_credential'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='expired_event_logged',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='is_destructive',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='short_action_summary',
            field=models.CharField(blank=True, max_length=500),
        ),
        migrations.CreateModel(
            name='McpApprovalSessionGrant',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('connection_id', models.CharField(blank=True, db_index=True, max_length=128)),
                ('expires_at', models.DateTimeField()),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                (
                    'agent',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='approval_session_grants',
                        to='agents.agent',
                    ),
                ),
                (
                    'company',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='mcp_approval_session_grants',
                        to='companies.company',
                    ),
                ),
                (
                    'granted_by',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='mcp_approval_session_grants',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
