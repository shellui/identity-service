# Backfill authority snapshot from linked regional agent.

from django.db import migrations


def forwards(apps, schema_editor):
    McpApprovalRequest = apps.get_model('agents', 'McpApprovalRequest')
    qs = McpApprovalRequest.objects.filter(agent_id__isnull=False).select_related('agent')
    for row in qs.iterator(chunk_size=500):
        agent = row.agent
        row.authority_grant_version = int(getattr(agent, 'grant_version', 0) or 0)
        row.authority_global_company_id = getattr(agent, 'global_company_id', None)
        row.authority_company_binding_version = getattr(agent, 'company_binding_version', None)
        row.save(
            update_fields=[
                'authority_grant_version',
                'authority_global_company_id',
                'authority_company_binding_version',
            ]
        )


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0014_mcpapprovalrequest_authority_snapshot'),
    ]

    operations = [
        migrations.RunPython(forwards, migrations.RunPython.noop),
    ]
