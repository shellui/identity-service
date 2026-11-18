# Snapshots on MCP agent refresh sessions for anti-downgrade checks.

from django.db import migrations, models


def forwards(apps, schema_editor):
    AgentRefreshSession = apps.get_model('agents', 'AgentRefreshSession')
    for row in AgentRefreshSession.objects.select_related('agent').iterator():
        agent = row.agent
        row.grant_version = int(getattr(agent, 'grant_version', 0) or 0)
        row.services_allowed = list(agent.services_allowed or [])
        row.access_mode = agent.access_mode or 'ask'
        row.read_level = agent.read_level or 'safe'
        row.allow_destructive = bool(agent.allow_destructive_without_asking)
        row.global_company_id = getattr(agent, 'global_company_id', None)
        row.company_binding_version = getattr(agent, 'company_binding_version', None)
        row.setup_company_id = getattr(agent, 'setup_company_id', None)
        row.setup_context_expires_at = getattr(agent, 'setup_context_expires_at', None)
        row.setup_new_company_grant = bool(getattr(agent, 'setup_new_company_grant', False))
        row.save(
            update_fields=[
                'grant_version',
                'services_allowed',
                'access_mode',
                'read_level',
                'allow_destructive',
                'global_company_id',
                'company_binding_version',
                'setup_company_id',
                'setup_context_expires_at',
                'setup_new_company_grant',
            ]
        )


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0016_agent_setup_grant_global_caps_callog_error'),
    ]

    operations = [
        migrations.AddField(
            model_name='agentrefreshsession',
            name='grant_version',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='agentrefreshsession',
            name='services_allowed',
            field=models.JSONField(default=list),
        ),
        migrations.AddField(
            model_name='agentrefreshsession',
            name='access_mode',
            field=models.CharField(default='ask', max_length=20),
        ),
        migrations.AddField(
            model_name='agentrefreshsession',
            name='read_level',
            field=models.CharField(default='safe', max_length=20),
        ),
        migrations.AddField(
            model_name='agentrefreshsession',
            name='allow_destructive',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='agentrefreshsession',
            name='global_company_id',
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='agentrefreshsession',
            name='company_binding_version',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='agentrefreshsession',
            name='setup_company_id',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='agentrefreshsession',
            name='setup_context_expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='agentrefreshsession',
            name='setup_new_company_grant',
            field=models.BooleanField(default=False),
        ),
        migrations.RunPython(forwards, migrations.RunPython.noop),
    ]
