import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scim', '0001_company_scim_token'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserScimAttributes',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'scim_id',
                    models.CharField(
                        blank=True,
                        db_index=True,
                        help_text='Published SCIM resource id (defaults to Django user pk).',
                        max_length=254,
                        null=True,
                        unique=True,
                    ),
                ),
                (
                    'scim_external_id',
                    models.CharField(
                        blank=True,
                        db_index=True,
                        default=None,
                        max_length=254,
                        null=True,
                    ),
                ),
                (
                    'scim_username',
                    models.CharField(blank=True, db_index=True, default=None, max_length=254, null=True),
                ),
                (
                    'user',
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='scim_attributes',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'verbose_name': 'User SCIM attributes',
                'verbose_name_plural': 'User SCIM attributes',
            },
        ),
    ]
