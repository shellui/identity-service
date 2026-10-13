from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0027_company_desktop_redirect_scheme'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='catalog_slug',
        ),
    ]
