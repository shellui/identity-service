import importlib

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.authapi.tests.test_migration_0014_oidc import _HistoricalApps, ensure_oidc_audit_table

User = get_user_model()
_migration = importlib.import_module('apps.authapi.migrations.0014_migrate_oidc_social_account_keys')


class OidcMigration0014UnresolvedProviderTests(TestCase):
    def test_issuer_without_provider_id_or_token_leaves_row_unchanged(self):
        user = User.objects.create_user(username='oidc-skip', email='skip@example.com', password='x')
        account = SocialAccount.objects.create(
            provider='openid_connect',
            uid='legacy-sub-only',
            user=user,
            extra_data={'userinfo': {'iss': 'https://issuer.example.com'}},
        )

        ensure_oidc_audit_table()
        _migration.forwards(_HistoricalApps(), None)

        account.refresh_from_db()
        self.assertEqual(account.provider, 'openid_connect')
        self.assertEqual(account.uid, 'legacy-sub-only')
