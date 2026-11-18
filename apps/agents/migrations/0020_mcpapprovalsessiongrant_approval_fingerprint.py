"""Link session grants to approval fingerprint (service, action, arguments_hash)."""

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0019_mcp_call_log_outcome_choices'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='approval_request',
            field=models.ForeignKey(
                null=True,
                blank=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='session_grants',
                to='agents.mcpapprovalrequest',
            ),
        ),
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='service',
            field=models.CharField(max_length=32, blank=True, default=''),
        ),
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='action',
            field=models.CharField(max_length=255, blank=True, default=''),
        ),
        migrations.AddField(
            model_name='mcpapprovalsessiongrant',
            name='arguments_hash',
            field=models.CharField(max_length=64, blank=True, default=''),
        ),
    ]
