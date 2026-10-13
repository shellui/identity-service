from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authapi', '0018_desktop_custom_scheme_redirect'),
    ]

    operations = [
        migrations.DeleteModel(
            name='OidcSocialAccountKeyMigration',
        ),
    ]
