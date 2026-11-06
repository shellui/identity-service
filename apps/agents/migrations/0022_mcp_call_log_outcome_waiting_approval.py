# Generated manually: normalize legacy pending_approval rows to waiting_approval.

from django.db import migrations


def forwards(apps, schema_editor):
    McpCallLog = apps.get_model('agents', 'McpCallLog')
    McpCallLog.objects.filter(outcome='pending_approval').update(outcome='waiting_approval')


def backwards(apps, schema_editor):
    McpCallLog = apps.get_model('agents', 'McpCallLog')
    McpCallLog.objects.filter(outcome='waiting_approval').update(outcome='pending_approval')


class Migration(migrations.Migration):
    dependencies = [
        ('agents', '0021_clear_mcp_arguments_redacted'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
