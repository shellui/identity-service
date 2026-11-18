# Clear legacy MCP arguments_redacted blobs (contract: no stored argument material).

from django.db import migrations


def clear_arguments_redacted(apps, schema_editor):
    McpApprovalRequest = apps.get_model('agents', 'McpApprovalRequest')
    McpCallLog = apps.get_model('agents', 'McpCallLog')
    McpApprovalRequest.objects.exclude(arguments_redacted={}).update(arguments_redacted={})
    McpCallLog.objects.exclude(arguments_redacted={}).update(arguments_redacted={})


class Migration(migrations.Migration):
    dependencies = [
        ('agents', '0020_mcpapprovalsessiongrant_approval_fingerprint'),
    ]

    operations = [
        migrations.RunPython(clear_arguments_redacted, migrations.RunPython.noop),
    ]
