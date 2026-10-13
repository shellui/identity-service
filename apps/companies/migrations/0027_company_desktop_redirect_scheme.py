from django.db import migrations, models


def delete_desktop_allowlist_rows(apps, schema_editor):
    CompanyOAuthRedirect = apps.get_model('companies', 'CompanyOAuthRedirect')
    CompanyOAuthRedirect.objects.filter(kind='desktop').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0026_desktop_custom_scheme_redirect'),
    ]

    operations = [
        migrations.AddField(
            model_name='company',
            name='desktop_redirect_scheme',
            field=models.CharField(
                blank=True,
                default='',
                help_text=(
                    'Lowercase custom URI scheme for desktop sign-in, for example shellui-playground. '
                    'Empty keeps desktop sign-in off. Redirects are accepted only when the scheme matches.'
                ),
                max_length=64,
            ),
        ),
        migrations.RunPython(delete_desktop_allowlist_rows, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='companyoauthredirect',
            name='kind',
        ),
        migrations.AlterField(
            model_name='companyoauthredirect',
            name='base_url',
            field=models.CharField(
                help_text='Canonical http(s) origin (https://app.example.com).',
                max_length=500,
            ),
        ),
    ]
