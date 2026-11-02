from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('agents', '0004_agent_services_saas'),
    ]

    operations = [
        migrations.AddField(
            model_name='agent',
            name='global_agent_id',
            field=models.UUIDField(
                blank=True,
                db_index=True,
                help_text='Global MCP agent id when this row was created by token exchange.',
                null=True,
            ),
        ),
        migrations.AddConstraint(
            model_name='agent',
            constraint=models.UniqueConstraint(
                condition=models.Q(('global_agent_id__isnull', False)),
                fields=('company', 'global_agent_id'),
                name='agents_company_global_agent_unique',
            ),
        ),
    ]
