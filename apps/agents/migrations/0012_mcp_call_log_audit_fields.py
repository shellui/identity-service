# Generated manually for trusted MCP call log audit fields.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0011_agent_permission_version_session_grant'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpcalllog',
            name='operation_title',
            field=models.CharField(blank=True, default='', max_length=500),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='access_kind',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='outcome',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='resource_label',
            field=models.CharField(blank=True, default='', max_length=500),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='company_name',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='approval_id',
            field=models.UUIDField(blank=True, null=True),
        ),
    ]
