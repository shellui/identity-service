from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0029_company_desktop_redirect_schemes'),
    ]

    operations = [
        migrations.AddField(
            model_name='company',
            name='allow_desktop_dev_scheme',
            field=models.BooleanField(
                default=False,
                help_text=(
                    'Accept the -dev variant of each scheme in Desktop redirect schemes when DEBUG is off. '
                    'For example, shellui-playground also allows shellui-playground-dev. Off by default.'
                ),
            ),
        ),
    ]
