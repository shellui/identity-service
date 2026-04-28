from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0005_companyoauthclient'),
        ('socialaccount', '0001_initial'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='companyoauthclient',
            name='company_oauth_client_unique_label_per_provider',
        ),
        migrations.RemoveConstraint(
            model_name='companyoauthclient',
            name='company_oauth_client_unique_client_id_per_provider',
        ),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='client_id',
        ),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='client_secret',
        ),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='label',
        ),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='provider',
        ),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='tenant',
        ),
        migrations.AddField(
            model_name='companyoauthclient',
            name='social_app',
            field=models.ForeignKey(
                null=True,
                on_delete=models.deletion.CASCADE,
                related_name='company_oauth_clients',
                to='socialaccount.socialapp',
            ),
        ),
        migrations.AlterField(
            model_name='companyoauthclient',
            name='social_app',
            field=models.ForeignKey(
                on_delete=models.deletion.CASCADE,
                related_name='company_oauth_clients',
                to='socialaccount.socialapp',
            ),
        ),
        migrations.AddConstraint(
            model_name='companyoauthclient',
            constraint=models.UniqueConstraint(
                fields=('company', 'social_app'),
                name='company_oauth_client_unique_social_app_per_company',
            ),
        ),
    ]
