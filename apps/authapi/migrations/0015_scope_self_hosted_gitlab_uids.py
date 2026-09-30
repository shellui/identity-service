"""Prefix self-hosted GitLab SocialAccount uids with the GitLab base URL.

gitlab.com rows stay unscoped so existing accounts keep matching.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from django.db import IntegrityError, migrations, transaction

logger = logging.getLogger(__name__)

_UID_MAX = 191
_GITLAB_COM = 'https://gitlab.com'


def _is_gitlab_com(base: str) -> bool:
    parsed = urlparse(base)
    host = (parsed.hostname or '').lower()
    path = (parsed.path or '').rstrip('/')
    return parsed.scheme.lower() == 'https' and host == 'gitlab.com' and not parsed.port and not path


def forwards(apps, schema_editor):
    SocialToken = apps.get_model('socialaccount', 'SocialToken')
    seen: set[int] = set()
    for token in SocialToken.objects.filter(account__provider='gitlab').select_related('account', 'app'):
        account = token.account
        if account.id in seen:
            continue
        seen.add(account.id)
        app = token.app
        settings = app.settings if isinstance(app.settings, dict) else {}
        base = str(settings.get('gitlab_url') or _GITLAB_COM).strip().rstrip('/')
        if _is_gitlab_com(base):
            continue
        raw_uid = str(account.uid or '').strip()
        if not raw_uid or '|' in raw_uid:
            continue
        new_uid = f'{base}|{raw_uid}'
        if len(new_uid) > _UID_MAX:
            logger.warning('GitLab uid migration skipped social_account_id=%s: uid too long', account.id)
            continue
        account.uid = new_uid
        try:
            with transaction.atomic():
                account.save(update_fields=['uid'])
        except IntegrityError:
            logger.warning(
                'GitLab uid migration left social_account_id=%s unchanged; uid %r already exists',
                account.id,
                new_uid,
            )


def backwards(apps, schema_editor):
    return


class Migration(migrations.Migration):
    dependencies = [
        ('authapi', '0014_migrate_oidc_social_account_keys'),
        ('socialaccount', '0006_alter_socialaccount_extra_data'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
