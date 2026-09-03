from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.authapi.oauth_confirm import build_oauth_confirm_token, parse_oauth_confirm_token

User = get_user_model()


class OAuthConfirmTokenTests(TestCase):
    def test_roundtrip(self):
        token = build_oauth_confirm_token(
            user_id=7,
            company_id=3,
            provider='github',
            redirect_to='http://127.0.0.1:9999/callback',
            avatar_url='https://example.com/a.png',
            company_oauth_client_id=2,
            client_timezone='Europe/Paris',
        )
        payload, err = parse_oauth_confirm_token(token)
        self.assertIsNone(err)
        assert payload is not None
        self.assertEqual(payload['user_id'], 7)
        self.assertEqual(payload['company_id'], 3)
        self.assertEqual(payload['provider'], 'github')
        self.assertEqual(payload['avatar_url'], 'https://example.com/a.png')

    def test_invalid_token(self):
        payload, err = parse_oauth_confirm_token('not-valid')
        self.assertIsNone(payload)
        self.assertIn('Invalid', err or '')
