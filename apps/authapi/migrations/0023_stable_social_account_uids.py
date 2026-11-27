"""Re-key Bitbucket, Pinterest and Tumblr social accounts to allauth's stable identifiers.

django-allauth 65.19.6 and 65.19.7 stopped using mutable names (a Bitbucket or Pinterest
username, a Tumblr blog name) as ``SocialAccount.uid``. Without this migration every
existing link from those providers stops matching, and the person is offered a new account.

Following allauth's upgrade notes, ``uid`` is filled from ``extra_data``:

- ``bitbucket_oauth2``: ``account_id``
- ``pinterest``: ``id``
- ``tumblr`` and ``tumblr_oauth2``: the ``uuid`` of the primary blog

A row is left alone when ``extra_data`` has no usable value, when it already holds the new
uid, or when another row of the same provider already owns that uid. Those rows are logged by
id (never their data) and the person links the account again. The migration is idempotent.
"""

from __future__ import annotations

import logging

from django.db import migrations, transaction

logger = logging.getLogger(__name__)

_UID_MAX = 191
PROVIDERS = ('bitbucket_oauth2', 'pinterest', 'tumblr', 'tumblr_oauth2')


def stable_uid(provider: str, extra_data) -> str | None:
    """The identifier allauth 65.19.7 and later use for ``provider``, or None when unknown."""
    if not isinstance(extra_data, dict):
        return None
    if provider == 'bitbucket_oauth2':
        value = extra_data.get('account_id')
    elif provider == 'pinterest':
        value = extra_data.get('id')
    elif provider in ('tumblr', 'tumblr_oauth2'):
        value = None
        blogs = extra_data.get('blogs')
        if isinstance(blogs, list):
            for blog in blogs:
                if isinstance(blog, dict) and blog.get('primary') and blog.get('uuid'):
                    value = blog['uuid']
                    break
    else:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value).strip()
    if not text or len(text) > _UID_MAX:
        return None
    return text


def rekey_social_accounts(apps, schema_editor):
    SocialAccount = apps.get_model('socialaccount', 'SocialAccount')
    unresolved: dict[str, list[int]] = {}
    migrated: dict[str, int] = {}
    for provider in PROVIDERS:
        for account in SocialAccount.objects.filter(provider=provider).order_by('pk').iterator():
            new_uid = stable_uid(provider, account.extra_data)
            if new_uid is None:
                unresolved.setdefault(provider, []).append(account.pk)
                continue
            if account.uid == new_uid:
                continue
            taken = SocialAccount.objects.filter(provider=provider, uid=new_uid).exclude(pk=account.pk).exists()
            if taken:
                unresolved.setdefault(provider, []).append(account.pk)
                continue
            with transaction.atomic():
                SocialAccount.objects.filter(pk=account.pk).update(uid=new_uid)
            migrated[provider] = migrated.get(provider, 0) + 1
    for provider, count in sorted(migrated.items()):
        logger.info('Re-keyed %s %s social accounts to stable uids.', count, provider)
    for provider, ids in sorted(unresolved.items()):
        logger.warning(
            '%s %s social accounts could not be re-keyed and need to link again. ids=%s',
            len(ids),
            provider,
            ids,
        )


class Migration(migrations.Migration):
    dependencies = [
        ('authapi', '0022_staff_admin_guard'),
        ('socialaccount', '0006_alter_socialaccount_extra_data'),
    ]

    operations = [
        migrations.RunPython(rekey_social_accounts, migrations.RunPython.noop),
    ]
