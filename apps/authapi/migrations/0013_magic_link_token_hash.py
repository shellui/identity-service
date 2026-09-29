import hashlib

from django.db import migrations, models


def _hash_plaintext_tokens(apps, schema_editor):
    MagicLinkToken = apps.get_model('authapi', 'MagicLinkToken')
    for row in MagicLinkToken.objects.all().iterator():
        digest = hashlib.sha256(row.token.encode('utf-8')).hexdigest()
        MagicLinkToken.objects.filter(pk=row.pk).update(token_hash=digest)


class Migration(migrations.Migration):

    dependencies = [
        (
            'authapi',
            '0012_rename_authapi_mag_company_6e1a2b_idx_authapi_mag_company_ab6619_idx',
        ),
    ]

    operations = [
        migrations.AddField(
            model_name='magiclinktoken',
            name='token_hash',
            field=models.CharField(db_index=True, max_length=64, null=True, unique=True),
        ),
        migrations.RunPython(_hash_plaintext_tokens, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='magiclinktoken',
            name='token',
        ),
        migrations.AlterField(
            model_name='magiclinktoken',
            name='token_hash',
            field=models.CharField(db_index=True, max_length=64, unique=True),
        ),
    ]
