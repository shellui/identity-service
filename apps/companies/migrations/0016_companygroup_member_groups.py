from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0015_companygroup_scim_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='companygroup',
            name='member_groups',
            field=models.ManyToManyField(
                blank=True,
                help_text='Nested SCIM group members (type Group). Same company only; cycles rejected.',
                related_name='parent_groups',
                to='companies.companygroup',
            ),
        ),
        migrations.AlterField(
            model_name='companygroup',
            name='members',
            field=models.ManyToManyField(
                blank=True,
                help_text='Direct user members (SCIM members with type User).',
                related_name='company_groups',
                to='auth.user',
            ),
        ),
    ]
