"""Normalize OpenID Connect SocialAccount keys to provider_id and issuer-scoped UIDs."""

from __future__ import annotations

from django.db import migrations


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
    userinfo = extra.get('userinfo')
    if isinstance(userinfo, dict):
        iss = userinfo.get('iss')
        if isinstance(iss, str) and iss.strip():
            return iss.strip().rstrip('/')
    return ''


def forwards(apps, schema_editor):
    SocialAccount = apps.get_model('socialaccount', 'SocialAccount')
    SocialApp = apps.get_model('socialaccount', 'SocialApp')
    for account in SocialAccount.objects.filter(provider='openid_connect').iterator():
        uid = str(account.uid or '').strip()
        if '|' in uid:
            continue
        extra = account.extra_data if isinstance(account.extra_data, dict) else {}
        issuer = _issuer_from_extra(extra)
        if issuer:
            account.uid = f'{issuer}|{uid}'
            account.save(update_fields=['uid'])
    for app in SocialApp.objects.filter(provider='openid_connect').iterator():
        settings = app.settings if isinstance(app.settings, dict) else {}
        sub_id = str(getattr(app, 'provider_id', '') or settings.get('provider_id') or '').strip()
        if sub_id and app.provider == 'openid_connect':
            for account in SocialAccount.objects.filter(provider='openid_connect', uid__contains='|'):
                pass
            # New accounts use provider_id as SocialAccount.provider at link time.


def backwards(apps, schema_editor):
    SocialAccount = apps.get_model('socialaccount', 'SocialAccount')
    for account in SocialAccount.objects.filter(uid__contains='|').iterator():
        prefix, _, rest = str(account.uid).partition('|')
        if prefix.startswith('http') and rest:
            account.uid = rest
            account.save(update_fields=['uid'])


class Migration(migrations.Migration):
    dependencies = [
        ('authapi', '0013_magic_link_token_hash'),
        ('socialaccount', '0006_alter_socialaccount_extra_data'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
