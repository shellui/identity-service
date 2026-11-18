from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0032_mcp_agents'),
    ]

    operations = [
        migrations.AddField(
            model_name='companyoauthclient',
            name='sso_verified_domains',
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    'Lowercase domains this IdP serves for MCP home-realm sign-in (Django admin only). '
                    'Must be listed on the company verified email domains. Empty means any verified domain '
                    'when this is the only SSO/OAuth client for the company.'
                ),
            ),
        ),
    ]
