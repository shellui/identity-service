from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0017_companygroup_source'),
    ]

    operations = [
        migrations.AddField(
            model_name='company',
            name='enable_magic_link',
            field=models.BooleanField(
                default=True,
                help_text=(
                    'When true (default for new companies), users can request passwordless email magic links '
                    'for this company. Requires deployment MAGIC_LINK_ENABLED.'
                ),
            ),
        ),
    ]
