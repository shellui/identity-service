from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('companies', '0013_companyoauthredirect'),
    ]

    operations = [
        migrations.AddField(
            model_name='companyoauthredirect',
            name='source',
            field=models.CharField(
                choices=[('manual', 'Manual'), ('hosting', 'Hosting')],
                default='manual',
                help_text='manual = owner-managed; hosting = synced from hosting-service preview sites.',
                max_length=20,
            ),
        ),
    ]
