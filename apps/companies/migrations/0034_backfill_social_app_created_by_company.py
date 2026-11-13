"""Set created_by_company_id on SocialApps mapped to exactly one company.

Provider-app create stores the owner on SocialApp.settings. Apps created before
that, or by staff in Django admin, have no owner key. Those apps are hidden from
the company that already uses them. This backfill sets the key only when every
CompanyOAuthClient for the app points at one company. Apps with no mapping, or
with mappings to more than one company, are left unchanged.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from django.db import migrations

logger = logging.getLogger(__name__)


def _settings_ready_for_owner(settings_data):
    """Return a copy of settings when created_by_company_id is missing, else None."""
    if settings_data is None:
        return {}
    if not isinstance(settings_data, dict):
        return None
    if settings_data.get('created_by_company_id') is not None:
        return None
    return dict(settings_data)


def backfill_social_app_created_by_company(apps, schema_editor):
    SocialApp = apps.get_model('socialaccount', 'SocialApp')
    CompanyOAuthClient = apps.get_model('companies', 'CompanyOAuthClient')
    companies_by_app: dict[int, set[int]] = defaultdict(set)
    rows = CompanyOAuthClient.objects.values_list('social_app_id', 'company_id')
    for social_app_id, company_id in rows.iterator():
        if social_app_id is None or company_id is None:
            continue
        companies_by_app[int(social_app_id)].add(int(company_id))

    pending = []
    for app in SocialApp.objects.all().iterator():
        companies = companies_by_app.get(app.pk) or set()
        if len(companies) != 1:
            continue
        settings_data = _settings_ready_for_owner(app.settings)
        if settings_data is None:
            continue
        settings_data['created_by_company_id'] = next(iter(companies))
        pending.append((app, settings_data))

    for app, settings_data in pending:
        app.settings = settings_data
        app.save(update_fields=['settings'])

    logger.info(
        'backfill created_by_company_id updated=%s',
        len(pending),
    )


class Migration(migrations.Migration):
    dependencies = [
        ('companies', '0033_companyoauthclient_sso_verified_domains'),
        ('socialaccount', '0006_alter_socialaccount_extra_data'),
    ]

    operations = [
        migrations.RunPython(backfill_social_app_created_by_company, migrations.RunPython.noop),
    ]
