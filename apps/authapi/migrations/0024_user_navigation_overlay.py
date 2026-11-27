# One navigation overlay per user and company.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('authapi', '0023_stable_social_account_uids'),
        ('companies', '0034_backfill_social_app_created_by_company'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserNavigationOverlay',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document', models.JSONField()),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                (
                    'company',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='navigation_overlays',
                        to='companies.company',
                    ),
                ),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='navigation_overlays',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ['user_id', 'company_id'],
            },
        ),
        migrations.AddConstraint(
            model_name='usernavigationoverlay',
            constraint=models.UniqueConstraint(
                fields=('user', 'company'),
                name='uniq_user_navigation_overlay_user_company',
            ),
        ),
    ]
