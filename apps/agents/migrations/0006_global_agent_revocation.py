from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('agents', '0005_agent_global_agent_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='GlobalAgentRevocation',
            fields=[
                ('global_agent_id', models.UUIDField(primary_key=True, serialize=False)),
                ('revoked_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
