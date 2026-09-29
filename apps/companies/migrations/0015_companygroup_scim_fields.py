from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0014_companyoauthredirect_source'),
    ]

    operations = [
        migrations.RenameField(
            model_name='companygroup',
            old_name='name',
            new_name='display_name',
        ),
        migrations.AddField(
            model_name='companygroup',
            name='external_id',
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text='SCIM externalId from the provisioning client (unique per company when set).',
                max_length=254,
                null=True,
            ),
        ),
        migrations.AlterModelOptions(
            name='companygroup',
            options={'ordering': ['display_name']},
        ),
        migrations.RemoveConstraint(
            model_name='companygroup',
            name='company_group_unique_name_per_company',
        ),
        migrations.AddConstraint(
            model_name='companygroup',
            constraint=models.UniqueConstraint(
                fields=('company', 'display_name'),
                name='company_group_unique_display_name_per_company',
            ),
        ),
        migrations.AddConstraint(
            model_name='companygroup',
            constraint=models.UniqueConstraint(
                condition=Q(external_id__isnull=False) & ~Q(external_id=''),
                fields=('company', 'external_id'),
                name='company_group_unique_external_id_per_company',
            ),
        ),
    ]
