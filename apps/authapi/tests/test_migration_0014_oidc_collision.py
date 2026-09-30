import importlib

from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
from django.apps import apps
from django.contrib.auth import get_user_model
from django.test import TestCase

User = get_user_model()
_migration = importlib.import_module('apps.authapi.migrations.0014_migrate_oidc_social_account_keys')


class OidcMigration0014CollisionTests(TestCase):
    def test_collision_leaves_losing_social_account_in_place(self):
        user_migrated = User.objects.create_user(username='oidc-win', email='w@example.com', password='x')
        user_pending = User.objects.create_user(username='oidc-lose', email='l@example.com', password='x')
        app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id='tenant-x',
            name='oidc-app',
            client_id='cid',
            secret='sec',
            settings={'server_url': 'https://issuer.example.com'},
        )
        migrated_uid = 'https://issuer.example.com|shared-sub'
        SocialAccount.objects.create(
            provider='tenant-x',
            uid=migrated_uid,
            user=user_migrated,
            extra_data={},
        )
        pending = SocialAccount.objects.create(
            provider='openid_connect',
            uid='shared-sub',
            user=user_pending,
            extra_data={'userinfo': {'iss': 'https://issuer.example.com'}},
        )
        SocialToken.objects.create(app=app, account=pending, token='tok')

        _migration.forwards(apps, None)

        pending.refresh_from_db()
        self.assertEqual(pending.provider, 'openid_connect')
        self.assertEqual(pending.uid, 'shared-sub')
