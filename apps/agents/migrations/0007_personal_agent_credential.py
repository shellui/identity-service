# Generated manually for personal MCP agent credentials and activity log fields.

import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0006_global_agent_revocation'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('companies', '0033_companyoauthclient_sso_verified_domains'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpcalllog',
            name='client_ip',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='result',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.CreateModel(
            name='PersonalAgentCredential',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('token_jti_digest', models.CharField(db_index=True, max_length=64)),
                ('expires_at', models.DateTimeField()),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                (
                    'agent',
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='personal_credential',
                        to='agents.agent',
                    ),
                ),
                (
                    'company',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='personal_agent_credentials',
                        to='companies.company',
                    ),
                ),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='personal_agent_credentials',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
