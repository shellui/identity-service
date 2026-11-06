# Setup grant flag, global permission caps, call log error_code.

from django.db import migrations, models


def forwards(apps, schema_editor):
    Agent = apps.get_model('agents', 'Agent')
    for agent in Agent.objects.all().iterator():
        agent.global_allowed_services = list(agent.services_allowed or [])
        agent.global_max_access_mode = agent.access_mode or 'ask'
        agent.global_max_read_level = agent.read_level or 'safe'
        agent.global_max_destructive = bool(agent.allow_destructive_without_asking)
        agent.save(
            update_fields=[
                'global_allowed_services',
                'global_max_access_mode',
                'global_max_read_level',
                'global_max_destructive',
            ]
        )


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0015_backfill_approval_authority'),
    ]

    operations = [
        migrations.AddField(
            model_name='agent',
            name='setup_new_company_grant',
            field=models.BooleanField(default=False, help_text='True when new-company setup context was delegated from a bound global subject token.'),
        ),
        migrations.AddField(
            model_name='agent',
            name='setup_mcp_session_ttl_seconds',
            field=models.PositiveIntegerField(blank=True, null=True, help_text='Signed mcp_session_ttl_seconds from global subject during active setup.'),
        ),
        migrations.AddField(
            model_name='agent',
            name='global_allowed_services',
            field=models.JSONField(default=list, help_text='Service ids allowed by the last global subject scope (exchange cap).'),
        ),
        migrations.AddField(
            model_name='agent',
            name='global_max_access_mode',
            field=models.CharField(default='ask', max_length=20),
        ),
        migrations.AddField(
            model_name='agent',
            name='global_max_read_level',
            field=models.CharField(default='safe', max_length=20),
        ),
        migrations.AddField(
            model_name='agent',
            name='global_max_destructive',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='error_code',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.RunPython(forwards, migrations.RunPython.noop),
    ]
