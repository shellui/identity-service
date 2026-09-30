from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0021_companyoauthclient_dedupe_constraint'),
    ]

    operations = [
        migrations.AddField(
            model_name='company',
            name='verified_email_domains',
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    'Lowercase domains Shellui has verified the company owns (DNS or equivalent). '
                    'Used for SAML email linking; not the same as allowed_email_domains.'
                ),
            ),
        ),
    ]
