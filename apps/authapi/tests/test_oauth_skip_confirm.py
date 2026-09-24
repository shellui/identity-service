from django.test import SimpleTestCase, override_settings

from apps.authapi.oauth import (
    oauth_identity_sufficient_for_auto_confirm,
    oauth_skip_confirm_provider_ids,
    should_skip_oauth_confirm,
)


class OAuthSkipConfirmHelperTests(SimpleTestCase):
    @override_settings(OAUTH_SKIP_CONFIRM_PROVIDERS=['google', 'GITHUB'])
    def test_skip_list_normalized(self):
        self.assertEqual(oauth_skip_confirm_provider_ids(), frozenset({'google', 'github'}))

    @override_settings(OAUTH_SKIP_CONFIRM_PROVIDERS=[])
    def test_empty_skip_list(self):
        self.assertFalse(should_skip_oauth_confirm('google', email='a@b.com', userinfo={}))

    @override_settings(OAUTH_SKIP_CONFIRM_PROVIDERS=['google'])
    def test_misconfigured_provider_not_matched(self):
        self.assertFalse(
            should_skip_oauth_confirm('googl', email='user@gmail.com', userinfo={'email_verified': True})
        )

    @override_settings(OAUTH_SKIP_CONFIRM_PROVIDERS=['google'])
    def test_synthetic_email_falls_back_to_confirm(self):
        self.assertFalse(
            should_skip_oauth_confirm(
                'google',
                email='sub123@google.local',
                userinfo={'sub': 'sub123'},
            )
        )

    @override_settings(OAUTH_SKIP_CONFIRM_PROVIDERS=['google'])
    def test_unverified_email_falls_back_to_confirm(self):
        self.assertFalse(
            oauth_identity_sufficient_for_auto_confirm(
                'google',
                email='user@gmail.com',
                userinfo={'email_verified': False},
            )
        )

    @override_settings(OAUTH_SKIP_CONFIRM_PROVIDERS=['google'])
    def test_google_verified_email_may_skip(self):
        self.assertTrue(
            should_skip_oauth_confirm(
                'google',
                email='user@gmail.com',
                userinfo={'email_verified': True},
            )
        )
