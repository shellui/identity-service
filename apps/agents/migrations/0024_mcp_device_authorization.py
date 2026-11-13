# RFC 8628 device authorization grants for company MCP clients.

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0023_mcp_call_log_global_activity'),
        ('companies', '0033_companyoauthclient_sso_verified_domains'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='McpDeviceAuthorization',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('device_code_digest', models.CharField(max_length=64, unique=True)),
                ('user_code_digest', models.CharField(max_length=64, unique=True)),
                ('resource', models.CharField(max_length=500)),
                ('scope', models.CharField(blank=True, default='', max_length=500)),
                (
                    'status',
                    models.CharField(
                        choices=[
                            ('pending', 'Pending'),
                            ('approved', 'Approved'),
                            ('denied', 'Denied'),
                            ('expired', 'Expired'),
                            ('consumed', 'Consumed'),
                        ],
                        default='pending',
                        max_length=20,
                    ),
                ),
                ('poll_interval', models.PositiveSmallIntegerField(default=5)),
                ('last_poll_at', models.DateTimeField(blank=True, null=True)),
                ('expires_at', models.DateTimeField()),
                ('approved_at', models.DateTimeField(blank=True, null=True)),
                ('denied_at', models.DateTimeField(blank=True, null=True)),
                ('consumed_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                (
                    'agent',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='device_authorizations',
                        to='agents.agent',
                    ),
                ),
                (
                    'client',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='device_authorizations',
                        to='agents.mcpoauthclient',
                    ),
                ),
                (
                    'company',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='device_authorizations',
                        to='companies.company',
                    ),
                ),
                (
                    'user',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='mcp_device_authorizations',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [models.Index(fields=['status', 'expires_at'], name='agents_mcpd_status_0abb2a_idx')],
            },
        ),
    ]
