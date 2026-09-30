import importlib

from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
from django.apps import apps
from django.contrib.auth import get_user_model
from django.test import TestCase

User = get_user_model()
_migration = importlib.import_module('apps.authapi.migrations.0014_migrate_oidc_social_account_keys')


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

        _migration.forwards(apps, None)

        account.refresh_from_db()
        self.assertEqual(account.provider, 'linked-tenant')
        self.assertEqual(account.uid, 'https://issuer.example.com|legacy-sub')

        Audit = apps.get_model('authapi', 'OidcSocialAccountKeyMigration')
        row = Audit.objects.get(social_account_id=account.id)
        self.assertEqual(row.old_provider, 'openid_connect')
        self.assertEqual(row.old_uid, 'legacy-sub')

        _migration.backwards(apps, None)
        account.refresh_from_db()
        self.assertEqual(account.provider, 'openid_connect')
        self.assertEqual(account.uid, 'legacy-sub')
