import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0018_company_enable_magic_link'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('authapi', '0010_refresh_rotation_oauth_session_code'),
    ]

    operations = [
        migrations.CreateModel(
            name='MagicLinkToken',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(db_index=True, max_length=254)),
                ('token', models.CharField(db_index=True, max_length=64, unique=True)),
                ('redirect_to', models.CharField(max_length=2048)),
                ('expires_at', models.DateTimeField(db_index=True)),
                ('consumed_at', models.DateTimeField(blank=True, db_index=True, null=True)),
                ('client_timezone', models.CharField(blank=True, max_length=64)),
                ('client_device_id', models.CharField(blank=True, max_length=128, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                (
                    'company',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='magic_link_tokens',
                        to='companies.company',
                    ),
                ),
                (
                    'user',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='magic_link_tokens',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [
                    models.Index(fields=['company', 'email', '-created_at'], name='authapi_mag_company_6e1a2b_idx'),
                ],
            },
        ),
    ]
