"""Normalize OpenID Connect SocialAccount keys to provider_id and issuer-scoped UIDs."""

from __future__ import annotations

import logging

import jwt
from django.db import IntegrityError, migrations, models, transaction

logger = logging.getLogger(__name__)


def _issuer_from_extra(extra: dict) -> str:
    if not isinstance(extra, dict):
        return ''
    if isinstance(extra.get('iss'), str) and extra['iss'].strip():
        return extra['iss'].strip().rstrip('/')
    id_token = extra.get('id_token')
    if isinstance(id_token, dict):
        iss = id_token.get('iss')
        if isinstance(iss, str) and iss.strip():
            return iss.strip().rstrip('/')
    if isinstance(id_token, str) and id_token.strip():
        try:
            claims = jwt.decode(
                id_token.strip(),
                options={'verify_signature': False},
                algorithms=['RS256', 'HS256', 'RS384', 'RS512'],
            )
        except Exception:
            claims = {}
        if isinstance(claims, dict):
            iss = claims.get('iss')
            if isinstance(iss, str) and iss.strip():
                return iss.strip().rstrip('/')
    userinfo = extra.get('userinfo')
    if isinstance(userinfo, dict):
        iss = userinfo.get('iss')
        if isinstance(iss, str) and iss.strip():
            return iss.strip().rstrip('/')
    return ''


def _issuer_for_app(app) -> str:
    settings = app.settings if isinstance(app.settings, dict) else {}
    server_url = str(settings.get('server_url') or '').strip().rstrip('/')
    return server_url


def _provider_id_for_app(app) -> str:
    sub_id = str(getattr(app, 'provider_id', '') or '').strip()
    if sub_id:
        return sub_id
    settings = app.settings if isinstance(app.settings, dict) else {}
    return str(settings.get('provider_id') or '').strip()


def forwards(apps, schema_editor):
    SocialAccount = apps.get_model('socialaccount', 'SocialAccount')
    SocialToken = apps.get_model('socialaccount', 'SocialToken')
    Audit = apps.get_model('authapi', 'OidcSocialAccountKeyMigration')
    migrated_ids: set[int] = set()

    def _migrate_account(account, *, provider_id: str, issuer: str) -> None:
        if not provider_id or not issuer:
            logger.warning(
                'OIDC migration skipped social_account_id=%s: missing provider_id or issuer',
                account.id,
            )
            return
        raw_uid = str(account.uid or '').strip()
        if '|' in raw_uid:
            _, _, raw_uid = raw_uid.partition('|')
        if not raw_uid:
            logger.warning('OIDC migration skipped social_account_id=%s: empty uid', account.id)
            return
        new_uid = f'{issuer}|{raw_uid}'
        new_provider = provider_id
        if account.provider == new_provider and account.uid == new_uid:
            return
        Audit.objects.create(
            social_account_id=account.id,
            old_provider=str(account.provider or ''),
            old_uid=str(account.uid or ''),
        )
        account.provider = new_provider
        account.uid = new_uid
        try:
            with transaction.atomic():
                account.save(update_fields=['provider', 'uid'])
        except IntegrityError:
            logger.warning(
                'OIDC migration left social_account_id=%s unchanged; '
                'target provider=%r uid=%r already exists',
                account.id,
                new_provider,
                new_uid,
            )
            migrated_ids.add(account.id)
            return
        migrated_ids.add(account.id)

    for token in SocialToken.objects.filter(
        account__provider='openid_connect',
    ).select_related('account', 'app'):
        account = token.account
        if account.id in migrated_ids:
            continue
        app = token.app
        if str(getattr(app, 'provider', '') or '') != 'openid_connect':
            continue
        provider_id = _provider_id_for_app(app)
        extra = account.extra_data if isinstance(account.extra_data, dict) else {}
        issuer = _issuer_from_extra(extra) or _issuer_for_app(app)
        _migrate_account(account, provider_id=provider_id, issuer=issuer)

    for account in SocialAccount.objects.filter(provider='openid_connect').iterator():
        if account.id in migrated_ids:
            continue
        extra = account.extra_data if isinstance(account.extra_data, dict) else {}
        issuer = _issuer_from_extra(extra)
        provider_id = str(extra.get('provider_id') or '').strip()
        if not issuer and not provider_id:
            logger.warning(
                'OIDC migration skipped social_account_id=%s: no issuer or provider_id in extra_data',
                account.id,
            )
            continue
        if not provider_id:
            provider_id = 'openid_connect'
        _migrate_account(account, provider_id=provider_id, issuer=issuer)


def backwards(apps, schema_editor):
    SocialAccount = apps.get_model('socialaccount', 'SocialAccount')
    Audit = apps.get_model('authapi', 'OidcSocialAccountKeyMigration')
    for row in Audit.objects.all().order_by('id'):
        try:
            account = SocialAccount.objects.get(pk=row.social_account_id)
        except SocialAccount.DoesNotExist:
            continue
        account.provider = row.old_provider
        account.uid = row.old_uid
        account.save(update_fields=['provider', 'uid'])
    Audit.objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [
        ('authapi', '0013_magic_link_token_hash'),
        ('socialaccount', '0006_alter_socialaccount_extra_data'),
    ]

    operations = [
        migrations.CreateModel(
            name='OidcSocialAccountKeyMigration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('social_account_id', models.BigIntegerField(db_index=True)),
                ('old_provider', models.CharField(max_length=200)),
                ('old_uid', models.CharField(max_length=255)),
                ('migrated_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.RunPython(forwards, backwards),
    ]
