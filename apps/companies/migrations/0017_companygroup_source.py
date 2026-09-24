from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0016_companygroup_member_groups'),
    ]

    operations = [
        migrations.AddField(
            model_name='companygroup',
            name='source',
            field=models.CharField(
                choices=[('manual', 'Manual'), ('scim', 'SCIM')],
                db_index=True,
                default='manual',
                help_text='manual = Shellui admin; scim = IdP provisioning (read-only in admin REST).',
                max_length=20,
            ),
        ),
    ]
