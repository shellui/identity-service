# Retained column. help_text only. Does not drop or rename access_global_metrics.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapi', '0020_cli_device_authorization'),
    ]

    operations = [
        migrations.AlterField(
            model_name='personalaccesstoken',
            name='access_global_metrics',
            field=models.BooleanField(
                default=False,
                help_text='Retained column. Global metrics access is no longer issued or accepted.',
            ),
        ),
    ]
