from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('companies', '0020_companyoauthclient_dedupe_key'),
    ]

    operations = [
        migrations.AddConstraint(
            model_name='companyoauthclient',
            constraint=models.UniqueConstraint(
                fields=('company', 'dedupe_key'),
                name='company_oauth_client_unique_dedupe_per_company',
            ),
        ),
    ]
