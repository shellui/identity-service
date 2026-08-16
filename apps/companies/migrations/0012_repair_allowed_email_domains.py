# Repair stringified domain lists accidentally saved via Django admin.

from django.db import migrations

from apps.companies.access import normalize_allowed_domains


def repair_allowed_email_domains(apps, schema_editor):
    Company = apps.get_model('companies', 'Company')
    for company in Company.objects.all().iterator():
        raw = company.allowed_email_domains
        fixed = normalize_allowed_domains(raw)
        if fixed != raw:
            company.allowed_email_domains = fixed
            company.save(update_fields=['allowed_email_domains'])


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0011_company_membership'),
    ]

    operations = [
        migrations.RunPython(repair_allowed_email_domains, migrations.RunPython.noop),
    ]
