# Convert Company.members to an explicit through model with per-company is_enabled.

import django.db.models.deletion
from django.conf import settings
from django.db import connection, migrations, models


def _old_members_table_exists() -> bool:
    tables = set(connection.introspection.table_names())
    return 'companies_company_members' in tables


def copy_existing_memberships(apps, schema_editor):
    """Copy rows from the auto M2M table into CompanyMembership before dropping it."""
    CompanyMembership = apps.get_model('companies', 'CompanyMembership')
    app_label, model_name = settings.AUTH_USER_MODEL.split('.')
    User = apps.get_model(app_label, model_name)

    if not _old_members_table_exists():
        return

    with connection.cursor() as cursor:
        cursor.execute('SELECT company_id, user_id FROM companies_company_members')
        rows = cursor.fetchall()

    for company_id, user_id in rows:
        enabled = True
        try:
            user = User.objects.only('is_active').get(pk=user_id)
            enabled = bool(user.is_active)
        except User.DoesNotExist:
            enabled = True
        CompanyMembership.objects.get_or_create(
            company_id=company_id,
            user_id=user_id,
            defaults={'is_enabled': enabled},
        )


def drop_old_members_table(apps, schema_editor):
    if not _old_members_table_exists():
        return
    with connection.cursor() as cursor:
        cursor.execute('DROP TABLE companies_company_members')


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0010_company_access_help_text'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='CompanyMembership',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'is_enabled',
                    models.BooleanField(
                        default=True,
                        help_text='When false, the user cannot obtain tokens for this company.',
                    ),
                ),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'company',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='memberships',
                        to='companies.company',
                    ),
                ),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='company_memberships',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ['company_id', 'user_id'],
            },
        ),
        migrations.AddConstraint(
            model_name='companymembership',
            constraint=models.UniqueConstraint(
                fields=('company', 'user'),
                name='company_membership_unique_user_per_company',
            ),
        ),
        migrations.RunPython(copy_existing_memberships, migrations.RunPython.noop),
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name='company',
                    name='members',
                    field=models.ManyToManyField(
                        blank=True,
                        related_name='companies',
                        through='companies.CompanyMembership',
                        through_fields=('company', 'user'),
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            database_operations=[
                migrations.RunPython(drop_old_members_table, migrations.RunPython.noop),
            ],
        ),
    ]
