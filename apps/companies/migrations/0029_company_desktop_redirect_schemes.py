from django.db import migrations, models


def copy_desktop_redirect_schemes(apps, schema_editor):
    """Copy non-empty per-provider schemes onto the company, one list, duplicates dropped."""
    Company = apps.get_model('companies', 'Company')
    CompanyOAuthClient = apps.get_model('companies', 'CompanyOAuthClient')
    for company in Company.objects.all().iterator():
        seen: list[str] = []
        found: set[str] = set()
        rows = CompanyOAuthClient.objects.filter(company_id=company.pk).order_by('id')
        for row in rows.iterator():
            scheme = (getattr(row, 'desktop_redirect_scheme', '') or '').strip().lower()
            if not scheme or scheme in found:
                continue
            found.add(scheme)
            seen.append(scheme)
        if seen:
            company.desktop_redirect_schemes = seen
            company.save(update_fields=['desktop_redirect_schemes'])


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0028_remove_companyoauthclient_catalog_slug'),
    ]

    operations = [
        migrations.AddField(
            model_name='company',
            name='desktop_redirect_schemes',
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    'Lowercase custom URI schemes for desktop apps that sign in to this company, '
                    'for example ["shellui-playground"]. Empty turns desktop sign-in off. '
                    'A redirect is accepted when its scheme is in this list.'
                ),
            ),
        ),
        migrations.RunPython(copy_desktop_redirect_schemes, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='desktop_redirect_scheme',
        ),
    ]
