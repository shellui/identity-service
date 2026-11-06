# Authority snapshot at approval create (stale after grant_version or binding change).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0013_rename_permission_version_to_grant_version'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='authority_grant_version',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='authority_global_company_id',
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpapprovalrequest',
            name='authority_company_binding_version',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]
