import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('companies', '0029_company_desktop_redirect_schemes'),
    ]

    operations = [
        migrations.CreateModel(
            name='AssertionUse',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('jti', models.CharField(max_length=128, unique=True)),
                ('idempotency_key', models.CharField(db_index=True, max_length=200)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='CompanyPlan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('limits', models.JSONField(default=dict)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'company',
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='plan_limits',
                        to='companies.company',
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name='ProvisioningReceipt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('idempotency_key', models.CharField(max_length=200, unique=True)),
                ('body_hash', models.CharField(max_length=64)),
                ('status_code', models.PositiveSmallIntegerField()),
                ('response_body', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='UpstreamAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('issuer', models.CharField(max_length=255)),
                ('sub', models.CharField(max_length=255)),
                ('email', models.EmailField(max_length=254)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='upstream_accounts',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name='VerifiedEmail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('verified_at', models.DateTimeField(auto_now=True)),
                (
                    'user',
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='federation_verified_email',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.AddConstraint(
            model_name='upstreamaccount',
            constraint=models.UniqueConstraint(fields=('issuer', 'sub'), name='federation_upstream_sub_unique'),
        ),
        migrations.AddConstraint(
            model_name='upstreamaccount',
            constraint=models.UniqueConstraint(
                fields=('user', 'issuer'),
                name='federation_upstream_user_issuer_unique',
            ),
        ),
    ]
