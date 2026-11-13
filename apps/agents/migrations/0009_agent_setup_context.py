"""Optional company setup context on regional agents after global token exchange."""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0008_mcp_approval_v1'),
    ]

    operations = [
        migrations.AddField(
            model_name='agent',
            name='setup_context_expires_at',
            field=models.DateTimeField(
                blank=True,
                help_text=(
                    'Absolute end of server-authorized new-company setup for this agent, '
                    'copied from the global subject token at token exchange. Empty when not in setup.'
                ),
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='agent',
            name='setup_company_id',
            field=models.PositiveIntegerField(
                blank=True,
                help_text='Company id the setup context applies to; must match company_id when set.',
                null=True,
            ),
        ),
    ]
