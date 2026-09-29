# Generated manually for OAuth provider dedupe keys.

from __future__ import annotations

from collections import defaultdict

from django.db import migrations, models


def _backfill_dedupe_keys(apps, schema_editor):
    CompanyOAuthClient = apps.get_model('companies', 'CompanyOAuthClient')
    SocialApp = apps.get_model('socialaccount', 'SocialApp')
    for row in CompanyOAuthClient.objects.select_related('social_app').iterator():
        try:
            app = row.social_app
        except SocialApp.DoesNotExist:
            continue
        from apps.authapi.oauth import social_app_catalog_slug
        from apps.companies.oauth_client_uniqueness import compute_oauth_client_dedupe_key

        slug = social_app_catalog_slug(app)
        row.catalog_slug = slug
        row.dedupe_key = compute_oauth_client_dedupe_key(app, catalog_slug=slug)
        row.save(update_fields=['catalog_slug', 'dedupe_key'])


def duplicate_dedupe_key_groups(CompanyOAuthClient) -> dict[tuple[int, str], list[int]]:
    groups: dict[tuple[int, str], list[int]] = defaultdict(list)
    for row in CompanyOAuthClient.objects.exclude(dedupe_key__isnull=True).exclude(dedupe_key='').iterator():
        groups[(row.company_id, row.dedupe_key)].append(row.id)
    return {key: ids for key, ids in groups.items() if len(ids) > 1}


def _report_duplicate_dedupe_keys(apps, schema_editor):
    CompanyOAuthClient = apps.get_model('companies', 'CompanyOAuthClient')
    duplicates = duplicate_dedupe_key_groups(CompanyOAuthClient)
    if not duplicates:
        return
    lines = ['company_oauth_client_dedupe_duplicates:']
    for (company_id, dedupe_key), row_ids in sorted(duplicates.items()):
        lines.append(
            f'  company_id={company_id} dedupe_key={dedupe_key!r} '
            f'company_oauth_client_ids={sorted(row_ids)}'
        )
    message = '\n'.join(lines)
    raise RuntimeError(
        f'{message}\nResolve duplicate OAuth company mappings, then re-run migrate.'
    )


class Migration(migrations.Migration):
    dependencies = [
        ('companies', '0019_alter_companygroup_display_name'),
        ('socialaccount', '0003_extra_data_default_dict'),
    ]

    operations = [
        migrations.AddField(
            model_name='companyoauthclient',
            name='catalog_slug',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
        migrations.AddField(
            model_name='companyoauthclient',
            name='dedupe_key',
            field=models.CharField(blank=True, max_length=512, null=True),
        ),
        migrations.RunPython(_backfill_dedupe_keys, migrations.RunPython.noop),
        migrations.RunPython(_report_duplicate_dedupe_keys, migrations.RunPython.noop),
    ]
