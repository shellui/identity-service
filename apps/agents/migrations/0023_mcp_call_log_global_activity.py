# Dashboard global-company activity may have no regional Agent row.

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0022_mcp_call_log_outcome_waiting_approval'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mcpcalllog',
            name='agent',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='call_logs',
                to='agents.agent',
            ),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='global_agent_id',
            field=models.UUIDField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='global_company_id',
            field=models.UUIDField(blank=True, null=True),
        ),
    ]
