from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.models import RefreshTokenSession
from apps.authapi.refresh_sessions import is_access_jti_denied
from apps.authapi.tokens import ShellUIAccessToken, ShellUIRefreshToken
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    OAUTH_TOKEN_DELIVERY='code',
)
class RefreshRotationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Refresh Co', slug='refresh-co')
        self.user = User.objects.create_user(
            username='refresh-user',
            email='refresh@example.com',
            password='secret',
        )
        set_company_access(self.company, self.user, enabled=True)
        self.company.members.add(self.user)

    def _issue_pair(self) -> dict:
        return _issue_shellui_tokens(self.user, company=self.company)

    def test_refresh_rotates_and_invalidates_previous_refresh(self):
        first = self._issue_pair()
        refresh_response = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': first['refresh_token']},
            format='json',
        )
        self.assertEqual(refresh_response.status_code, 200, refresh_response.data)
        second = refresh_response.data

        third = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': second['refresh_token']},
            format='json',
        )
        self.assertEqual(third.status_code, 200)

        stale = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': first['refresh_token']},
            format='json',
        )
        self.assertEqual(stale.status_code, 401)
        self.assertIn('revoked', stale.data['error'].lower())

    def test_logout_revokes_refresh_and_access(self):
        payload = self._issue_pair()
        access = payload['access_token']
        refresh = payload['refresh_token']

        logout = self.client.post(
            '/api/v1/logout',
            {'refresh_token': refresh},
            HTTP_AUTHORIZATION=f'Bearer {access}',
            format='json',
        )
        self.assertEqual(logout.status_code, 200)

        refresh_response = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': refresh},
            format='json',
        )
        self.assertEqual(refresh_response.status_code, 401)

        access_token = ShellUIAccessToken(access)
        self.assertTrue(is_access_jti_denied(str(access_token['jti'])))

        profile = self.client.get(
            '/api/v1/user',
            HTTP_AUTHORIZATION=f'Bearer {access}',
        )
        self.assertEqual(profile.status_code, 401)

    def test_reuse_of_rotated_refresh_revokes_family(self):
        first = self._issue_pair()
        rotated = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': first['refresh_token']},
            format='json',
        )
        self.assertEqual(rotated.status_code, 200)
        second_refresh = rotated.data['refresh_token']

        reuse = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': first['refresh_token']},
            format='json',
        )
        self.assertEqual(reuse.status_code, 401)

        blocked = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': second_refresh},
            format='json',
        )
        self.assertEqual(blocked.status_code, 401)

        self.assertEqual(
            RefreshTokenSession.objects.filter(
                user=self.user,
                revoked_at__isnull=False,
            ).count(),
            2,
        )

    def test_refresh_without_registered_session_is_rejected(self):
        orphan = ShellUIRefreshToken.for_user(self.user)
        orphan['company_id'] = self.company.id
        response = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': str(orphan)},
            format='json',
        )
        self.assertEqual(response.status_code, 401)


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    OAUTH_TOKEN_DELIVERY='code',
)
class OAuthSessionCodeDeliveryTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Code Co', slug='code-co')
        self.user = User.objects.create_user(
            username='code-user',
            email='code@example.com',
            password='secret',
        )
        set_company_access(self.company, self.user, enabled=True)

    def test_issue_and_redeem_session_code(self):
        payload = _issue_shellui_tokens(self.user, company=self.company, oauth_provider='github')
        from apps.authapi.oauth_session_code import create_oauth_session_delivery_code, redeem_oauth_session_code

        redirect_to = 'http://127.0.0.1:4000/login/callback'
        row = create_oauth_session_delivery_code(
            user=self.user,
            company=self.company,
            redirect_to=redirect_to,
            token_payload={**payload, 'provider': 'github'},
        )
        redeemed, err = redeem_oauth_session_code(
            code=row.code,
            redirect_to=redirect_to,
            request_origin='http://127.0.0.1:4000',
        )
        self.assertIsNone(err)
        assert redeemed is not None
        self.assertEqual(redeemed['access_token'], payload['access_token'])

        again, err2 = redeem_oauth_session_code(
            code=row.code,
            redirect_to=redirect_to,
        )
        self.assertIsNone(again)
        self.assertIn('already used', err2 or '')

    def test_oauth_session_endpoint(self):
        payload = _issue_shellui_tokens(self.user, company=self.company)
        from apps.authapi.oauth_session_code import create_oauth_session_delivery_code

        redirect_to = 'http://127.0.0.1:5555/callback'
        row = create_oauth_session_delivery_code(
            user=self.user,
            company=self.company,
            redirect_to=redirect_to,
            token_payload={**payload, 'provider': 'github'},
        )
        response = self.client.post(
            '/api/v1/oauth/session',
            {'auth_code': row.code, 'redirect_to': redirect_to},
            format='json',
            HTTP_ORIGIN='http://127.0.0.1:5555',
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
