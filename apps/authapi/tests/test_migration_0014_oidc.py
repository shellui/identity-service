import importlib

from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import connection, models
from django.test import TestCase

User = get_user_model()
_migration = importlib.import_module('apps.authapi.migrations.0014_migrate_oidc_social_account_keys')


class OidcSocialAccountKeyMigration(models.Model):
    social_account_id = models.BigIntegerField()
    old_provider = models.CharField(max_length=200)
    old_uid = models.CharField(max_length=255)
    migrated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'authapi'
        db_table = 'authapi_oidcsocialaccountkeymigration'
        managed = False


class _HistoricalApps:
    def get_model(self, app_label, model_name):
        if app_label == 'authapi' and model_name == 'OidcSocialAccountKeyMigration':
            return OidcSocialAccountKeyMigration
        return apps.get_model(app_label, model_name)


def ensure_oidc_audit_table() -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS authapi_oidcsocialaccountkeymigration (
                id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
                social_account_id bigint NOT NULL,
                old_provider varchar(200) NOT NULL,
                old_uid varchar(255) NOT NULL,
                migrated_at datetime NOT NULL
            )
            '''
        )


class OidcMigration0014Tests(TestCase):
    def test_forwards_migrates_existing_openid_connect_rows(self):
        user = User.objects.create_user(username='oidc-mig', email='oidc-mig@example.com', password='x')
        app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id='linked-tenant',
            name='oidc-mig-app',
            client_id='cid-mig',
            secret='sec',
            settings={'server_url': 'https://issuer.example.com', 'catalog_slug': 'linkedin'},
        )
        account = SocialAccount.objects.create(
            provider='openid_connect',
            uid='legacy-sub',
            user=user,
            extra_data={'userinfo': {'iss': 'https://issuer.example.com'}},
        )
        SocialToken.objects.create(app=app, account=account, token='tok')

        ensure_oidc_audit_table()
        historical = _HistoricalApps()
        _migration.forwards(historical, None)

        account.refresh_from_db()
        self.assertEqual(account.provider, 'linked-tenant')
        self.assertEqual(account.uid, 'https://issuer.example.com|legacy-sub')

        row = OidcSocialAccountKeyMigration.objects.get(social_account_id=account.id)
        self.assertEqual(row.old_provider, 'openid_connect')
        self.assertEqual(row.old_uid, 'legacy-sub')

        _migration.backwards(historical, None)
        account.refresh_from_db()
        self.assertEqual(account.provider, 'openid_connect')
        self.assertEqual(account.uid, 'legacy-sub')
