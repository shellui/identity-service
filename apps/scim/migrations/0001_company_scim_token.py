import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('companies', '0014_companyoauthredirect_source'),
    ]

    operations = [
        migrations.CreateModel(
            name='CompanyScimToken',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('token_prefix', models.CharField(db_index=True, max_length=16)),
                ('token_hash', models.CharField(max_length=64, unique=True)),
                ('name', models.CharField(blank=True, max_length=200)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('revoked_at', models.DateTimeField(blank=True, db_index=True, null=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                (
                    'company',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='scim_tokens',
                        to='companies.company',
                    ),
                ),
            ],
            options={
                'verbose_name': 'Company SCIM token',
                'verbose_name_plural': 'Company SCIM tokens',
                'ordering': ['-created_at'],
                'indexes': [models.Index(fields=['company', '-created_at'], name='scim_company_created_idx')],
            },
        ),
    ]
