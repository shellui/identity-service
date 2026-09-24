import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0017_companygroup_source'),
        ('scim', '0002_user_scim_attributes'),
    ]

    operations = [
        migrations.CreateModel(
            name='CompanyScimProvisioningState',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_error_at', models.DateTimeField(blank=True, null=True)),
                ('last_error_code', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('last_error_type', models.CharField(blank=True, default='', max_length=64)),
                ('last_error_detail', models.JSONField(blank=True, default=dict)),
                (
                    'company',
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='scim_provisioning_state',
                        to='companies.company',
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name='ScimProvisioningEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'event_type',
                    models.CharField(
                        choices=[('group_display_name_conflict', 'Group display name conflict')],
                        db_index=True,
                        max_length=64,
                    ),
                ),
                (
                    'channel',
                    models.CharField(
                        choices=[('scim', 'SCIM'), ('admin', 'Admin REST')],
                        max_length=16,
                    ),
                ),
                ('detail', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    'company',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='scim_provisioning_events',
                        to='companies.company',
                    ),
                ),
                (
                    'scim_token',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='provisioning_events',
                        to='scim.companyscimtoken',
                    ),
                ),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='scimprovisioningevent',
            index=models.Index(fields=['company', '-created_at'], name='scim_scimpr_company_6a8b0d_idx'),
        ),
        migrations.AddIndex(
            model_name='scimprovisioningevent',
            index=models.Index(
                fields=['company', 'event_type', '-created_at'],
                name='scim_scimpr_company_2f4c91_idx',
            ),
        ),
    ]
