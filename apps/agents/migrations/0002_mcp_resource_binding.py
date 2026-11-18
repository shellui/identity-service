from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0001_mcp_agents'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpauthorizationcode',
            name='resource',
            field=models.CharField(blank=True, default='', max_length=500),
        ),
        migrations.AddField(
            model_name='agentrefreshsession',
            name='resource',
            field=models.CharField(blank=True, default='', max_length=500),
        ),
    ]
