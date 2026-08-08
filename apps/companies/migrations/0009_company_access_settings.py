# Generated manually for company access settings

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0008_metrics_api_key'),
    ]

    operations = [
        migrations.AddField(
            model_name='company',
            name='access_mode',
            field=models.CharField(
                choices=[
                    ('public', 'Public'),
                    ('domain', 'Domain'),
                    ('invite', 'Invitation only'),
                ],
                default='public',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='company',
            name='allowed_email_domains',
            field=models.JSONField(blank=True, default=list),
        ),
    ]
