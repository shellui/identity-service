import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapi', '0021_personal_access_token_global_metrics_unused'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='StaffAdminGuard',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                ('totp_secret', models.CharField(blank=True, default='', max_length=64)),
                ('totp_confirmed_at', models.DateTimeField(blank=True, null=True)),
                ('failed_attempts', models.PositiveIntegerField(default=0)),
                ('locked_until', models.DateTimeField(blank=True, null=True)),
                (
                    'user',
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='staff_admin_guard',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
