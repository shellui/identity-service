# Store how an MCP approval was decided, and which client asked.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0025_rename_identity_mcp_tool_names'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='consent',
            field=models.CharField(
                blank=True,
                choices=[('in_chat', 'In chat'), ('link', 'Link')],
                default='',
                help_text='How this request was decided: in_chat or link. Empty when the decision did not say.',
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='client_name',
            field=models.CharField(
                blank=True,
                default='',
                help_text='MCP client that asked for this decision. Empty when the caller did not send a name.',
                max_length=80,
            ),
        ),
    ]
