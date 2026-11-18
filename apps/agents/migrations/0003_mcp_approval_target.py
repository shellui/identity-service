from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('agents', '0002_mcp_resource_binding'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='target',
            field=models.CharField(blank=True, max_length=500),
        ),
    ]
