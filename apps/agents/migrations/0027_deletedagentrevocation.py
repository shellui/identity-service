import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0026_mcpapprovalrequest_consent'),
    ]

    operations = [
        migrations.CreateModel(
            name='DeletedAgentRevocation',
            fields=[
                ('agent_id', models.UUIDField(primary_key=True, serialize=False)),
                ('company_id', models.PositiveIntegerField(db_index=True)),
                ('deleted_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('token_expires_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
            ],
            options={
                'ordering': ['-deleted_at'],
            },
        ),
    ]
