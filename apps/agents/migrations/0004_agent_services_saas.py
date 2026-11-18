from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0003_mcp_approval_target'),
    ]

    operations = [
        migrations.AlterField(
            model_name='agent',
            name='services_allowed',
            field=models.JSONField(
                default=list,
                help_text='List of service ids: identity, storage, hosting, email, saas.',
            ),
        ),
    ]
