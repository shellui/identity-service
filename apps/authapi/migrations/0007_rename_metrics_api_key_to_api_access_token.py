# Renames MetricsApiKey → ApiAccessToken (table authapi_metricsapikey → authapi_apiaccesstoken).

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authapi', '0006_metrics_api_key'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='MetricsApiKey',
            new_name='ApiAccessToken',
        ),
        migrations.AlterModelOptions(
            name='apiaccesstoken',
            options={
                'ordering': ['-created_at'],
                'verbose_name': 'API access token',
                'verbose_name_plural': 'API access tokens',
            },
        ),
    ]
