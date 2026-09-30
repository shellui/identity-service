# SAML PR #70: renumber this migration if companies 0022+ collides with parallel work (e.g. OAuth PR #69).
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
                    'Domains set by Shellui operators in Django admin after ownership proof. '
                    'Used for SAML email linking; not the same as allowed_email_domains.'
                ),
            ),
        ),
    ]
