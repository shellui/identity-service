"""Prefix self-hosted GitLab SocialAccount uids with the GitLab base URL.

Login stores the SocialAccount and does not write a SocialToken, so this
migration starts from SocialAccount rows whose provider is gitlab.

The GitLab base URL comes from the account's token app when one exists.
Otherwise it comes from the user's companies: a single GitLab SocialApp
linked through CompanyOAuthClient. gitlab.com rows stay raw.

Ambiguous rows, and rows that cannot be rewritten, fail the migration
with their ids. Bind a row with:

    python manage.py scope_gitlab_social_uids --account-id ID --social-app-id APP_ID

Then run migrate again.
"""

from __future__ import annotations

from urllib.parse import urlparse

from django.db import IntegrityError, migrations, transaction

_UID_MAX = 191
_GITLAB_COM = 'https://gitlab.com'


class GitlabUidMigrationError(Exception):
    """One or more GitLab SocialAccount rows cannot be scoped safely."""

    def __init__(self, failures: list[tuple[int, str]]):
        self.failures = list(failures)
        ids = ', '.join(str(account_id) for account_id, _reason in self.failures)
        details = '; '.join(f'social_account_id={account_id}: {reason}' for account_id, reason in self.failures)
        super().__init__(
            'GitLab uid migration failed for social_account ids '
            f'{ids}. {details}. '
            'Bind each row to one GitLab SocialApp with '
            '`python manage.py scope_gitlab_social_uids --account-id ID --social-app-id APP_ID`, '
            'then run migrate again.'
        )


def _is_gitlab_com(base: str) -> bool:
    parsed = urlparse(base)
    host = (parsed.hostname or '').lower()
    path = (parsed.path or '').rstrip('/')
    return parsed.scheme.lower() == 'https' and host == 'gitlab.com' and not parsed.port and not path


def _gitlab_base_from_settings(settings) -> str:
    if not isinstance(settings, dict):
        settings = {}
    return str(settings.get('gitlab_url') or _GITLAB_COM).strip().rstrip('/')


def _bases_for_account(account, SocialToken, CompanyMembership, CompanyOAuthClient) -> set[str]:
    """GitLab base URLs that could apply to this account. Token apps win when present."""
    token_bases: list[str] = []
    tokens = SocialToken.objects.filter(account_id=account.id).select_related('app')
    for token in tokens:
        app = token.app
        if app is None or str(getattr(app, 'provider', '') or '') != 'gitlab':
            continue
        token_bases.append(_gitlab_base_from_settings(getattr(app, 'settings', None)))
    if token_bases:
        return set(token_bases)

    company_ids = list(
        CompanyMembership.objects.filter(user_id=account.user_id).values_list('company_id', flat=True)
    )
    if not company_ids:
        return set()
    clients = CompanyOAuthClient.objects.filter(
        company_id__in=company_ids,
        social_app__provider='gitlab',
    ).select_related('social_app')
    return {
        _gitlab_base_from_settings(client.social_app.settings)
        for client in clients
        if getattr(client, 'social_app_id', None)
    }


def _plan_uid(uid: str, base: str) -> tuple[str | None, str | None]:
    """Return (new uid, error). A null new uid with no error means leave the row alone."""
    current = str(uid or '').strip()
    if _is_gitlab_com(base):
        if '|' in current:
            return None, 'gitlab.com uid contains a pipe and cannot stay a raw id'
        return None, None
    if not current:
        return None, 'empty uid'
    prefix = f'{base}|'
    if current.startswith(prefix):
        rest = current[len(prefix):]
        if rest and '|' not in rest:
            return None, None
        return None, 'uid pipe does not match the resolved GitLab base'
    if '|' in current:
        return None, 'uid already contains a pipe and cannot be prefixed'
    new_uid = f'{base}|{current}'
    if len(new_uid) > _UID_MAX:
        return None, f'scoped uid is longer than {_UID_MAX} characters'
    return new_uid, None


def gitlab_uid_migration_plan(SocialAccount, SocialToken, CompanyMembership, CompanyOAuthClient):
    """Split gitlab SocialAccount rows into safe updates and hard failures."""
    failures: list[tuple[int, str]] = []
    updates: list[tuple[object, str]] = []
    for account in SocialAccount.objects.filter(provider='gitlab').order_by('id'):
        bases = _bases_for_account(account, SocialToken, CompanyMembership, CompanyOAuthClient)
        if not bases:
            failures.append((account.id, 'no GitLab SocialApp (no token, and no single company GitLab app)'))
            continue
        if len(bases) > 1:
            listed = ', '.join(sorted(bases))
            failures.append((account.id, f'ambiguous GitLab base ({listed})'))
            continue
        base = next(iter(bases))
        new_uid, error = _plan_uid(account.uid, base)
        if error:
            failures.append((account.id, error))
            continue
        if not new_uid or new_uid == account.uid:
            continue
        taken = SocialAccount.objects.filter(provider='gitlab', uid=new_uid).exclude(pk=account.pk).exists()
        if taken:
            failures.append((account.id, f'target uid {new_uid!r} already exists'))
            continue
        updates.append((account, new_uid))
    return failures, updates


def forwards(apps, schema_editor):
    SocialAccount = apps.get_model('socialaccount', 'SocialAccount')
    SocialToken = apps.get_model('socialaccount', 'SocialToken')
    CompanyMembership = apps.get_model('companies', 'CompanyMembership')
    CompanyOAuthClient = apps.get_model('companies', 'CompanyOAuthClient')
    failures, updates = gitlab_uid_migration_plan(
        SocialAccount,
        SocialToken,
        CompanyMembership,
        CompanyOAuthClient,
    )
    if failures:
        raise GitlabUidMigrationError(failures)
    save_failures: list[tuple[int, str]] = []
    for account, new_uid in updates:
        account.uid = new_uid
        try:
            with transaction.atomic():
                account.save(update_fields=['uid'])
        except IntegrityError:
            save_failures.append((account.id, f'target uid {new_uid!r} already exists'))
    if save_failures:
        raise GitlabUidMigrationError(save_failures)


def backwards(apps, schema_editor):
    return


class Migration(migrations.Migration):
    dependencies = [
        ('authapi', '0014_migrate_oidc_social_account_keys'),
        ('socialaccount', '0006_alter_socialaccount_extra_data'),
        ('companies', '0022_company_verified_email_domains'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
