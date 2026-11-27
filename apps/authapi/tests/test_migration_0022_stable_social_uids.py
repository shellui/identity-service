import importlib

from allauth.socialaccount.models import SocialAccount
from django.apps import apps
from django.contrib.auth import get_user_model
from django.test import TestCase

User = get_user_model()
_migration = importlib.import_module('apps.authapi.migrations.0022_stable_social_account_uids')


def _account(provider: str, uid: str, extra_data, name: str):
    user = User.objects.create_user(username=name, email=f'{name}@example.com', password='x')
    return SocialAccount.objects.create(user=user, provider=provider, uid=uid, extra_data=extra_data)


class StableSocialUidMigrationTests(TestCase):
    def _run(self):
        _migration.rekey_social_accounts(apps, None)

    def test_bitbucket_uses_account_id(self):
        row = _account('bitbucket_oauth2', 'old-username', {'account_id': '5d1f-abc', 'username': 'old-username'}, 'bb')
        self._run()
        row.refresh_from_db()
        self.assertEqual(row.uid, '5d1f-abc')

    def test_pinterest_uses_id(self):
        row = _account('pinterest', 'old-name', {'id': '8123456', 'username': 'old-name'}, 'pin')
        self._run()
        row.refresh_from_db()
        self.assertEqual(row.uid, '8123456')

    def test_pinterest_numeric_id_becomes_text(self):
        row = _account('pinterest', 'old-name', {'id': 8123456}, 'pin-int')
        self._run()
        row.refresh_from_db()
        self.assertEqual(row.uid, '8123456')

    def test_tumblr_uses_primary_blog_uuid(self):
        extra = {
            'name': 'me',
            'blogs': [
                {'name': 'side', 'uuid': 't:side-uuid', 'primary': False},
                {'name': 'main', 'uuid': 't:main-uuid', 'primary': True},
            ],
        }
        for provider in ('tumblr', 'tumblr_oauth2'):
            with self.subTest(provider=provider):
                row = _account(provider, 'main', extra, f'tb-{provider}')
                self._run()
                row.refresh_from_db()
                self.assertEqual(row.uid, 't:main-uuid')

    def test_rows_without_a_usable_value_are_left_alone(self):
        rows = [
            _account('bitbucket_oauth2', 'keep-1', {}, 'a1'),
            _account('pinterest', 'keep-2', {'username': 'x'}, 'a2'),
            _account('tumblr_oauth2', 'keep-3', {'blogs': [{'name': 'b', 'primary': True}]}, 'a3'),
            _account('tumblr_oauth2', 'keep-4', {'blogs': 'nope'}, 'a4'),
            _account('pinterest', 'keep-5', {'id': True}, 'a5'),
            _account('pinterest', 'keep-6', [], 'a6'),
        ]
        with self.assertLogs(_migration.logger, level='WARNING') as logs:
            self._run()
        for row in rows:
            before = row.uid
            row.refresh_from_db()
            self.assertEqual(row.uid, before)
        self.assertTrue(any('could not be re-keyed' in line for line in logs.output))
        # The log names ids and counts only, never account data.
        self.assertNotIn('example.com', '\n'.join(logs.output))

    def test_a_uid_already_taken_by_another_row_is_not_overwritten(self):
        owner = _account('pinterest', '777', {'id': '777'}, 'owner')
        other = _account('pinterest', 'old-name', {'id': '777'}, 'other')
        with self.assertLogs(_migration.logger, level='WARNING'):
            self._run()
        owner.refresh_from_db()
        other.refresh_from_db()
        self.assertEqual(owner.uid, '777')
        self.assertEqual(other.uid, 'old-name')

    def test_other_providers_are_untouched(self):
        row = _account('github', 'gh-1', {'id': 999, 'account_id': 'x'}, 'gh')
        self._run()
        row.refresh_from_db()
        self.assertEqual(row.uid, 'gh-1')

    def test_idempotent(self):
        row = _account('pinterest', 'old-name', {'id': '42'}, 'twice')
        self._run()
        self._run()
        row.refresh_from_db()
        self.assertEqual(row.uid, '42')

    def test_stable_uid_helper(self):
        self.assertIsNone(_migration.stable_uid('github', {'id': 1}))
        self.assertEqual(_migration.stable_uid('bitbucket_oauth2', {'account_id': ' abc '}), 'abc')
        self.assertIsNone(_migration.stable_uid('pinterest', {'id': 'x' * 200}))
