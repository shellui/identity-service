from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient

from apps.authapi.oauth_user import OAuthProfile, resolve_oauth_user
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()


def _github_profile(email: str, full_name: str, uid: str = '4242') -> OAuthProfile:
    return OAuthProfile(
        provider_id=uid,
        social_provider='github',
        social_uid=uid,
        email=email,
        full_name=full_name,
        avatar_url=None,
        email_verified_for_link=True,
        userinfo={'id': uid, 'name': full_name},
    )


class UserDisplayNameUpdateTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.company = Company.objects.create(name='Name Co', slug='name-co')
        self.user = User.objects.create_user(
            username='sebastien',
            email='sebastien@example.com',
            password='unused',
        )
        set_company_access(self.company, self.user, enabled=True)
        tokens = _issue_shellui_tokens(self.user, company=self.company)
        self.tokens = tokens
        self.auth = f'Bearer {tokens["access_token"]}'

    def _patch(self, body):
        return self.client.patch('/api/v1/user', body, format='json', HTTP_AUTHORIZATION=self.auth)

    def test_patch_sets_first_and_last_name(self):
        response = self._patch({'name': '  Ada   King Lovelace '})

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['user_metadata']['name'], 'Ada King Lovelace')
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Ada')
        self.assertEqual(self.user.last_name, 'King Lovelace')

    def test_single_word_name_clears_last_name(self):
        self.user.first_name = 'Old'
        self.user.last_name = 'Name'
        self.user.save()

        response = self._patch({'name': 'Seb'})

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual((self.user.first_name, self.user.last_name), ('Seb', ''))

    def test_blank_or_missing_name_rejected(self):
        for body in ({'name': '   '}, {'name': ''}, {}):
            with self.subTest(body=body):
                self.assertEqual(self._patch(body).status_code, 400)
        self.assertEqual(self._patch({'name': 'x' * 151}).status_code, 400)

    def test_stale_cached_metadata_name_is_replaced(self):
        cache.set(
            f'shellui:user_metadata:{self.user.id}',
            {'name': 'magic_sebastien_93d71bc4', 'full_name': 'magic_sebastien_93d71bc4'},
        )

        self._patch({'name': 'Sébastien'})
        profile = self.client.get('/api/v1/user', HTTP_AUTHORIZATION=self.auth)

        self.assertEqual(profile.data['user_metadata']['name'], 'Sébastien')
        self.assertEqual(profile.data['user_metadata']['full_name'], 'Sébastien')

    def test_put_metadata_cannot_override_name(self):
        self._patch({'name': 'Ada'})

        response = self.client.put(
            '/api/v1/user',
            {'data': {'name': 'Someone else'}},
            format='json',
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(response.data['user_metadata']['name'], 'Ada')

    def test_refreshed_token_carries_new_name(self):
        import jwt

        self._patch({'name': 'Ada Lovelace'})
        refreshed = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': self.tokens['refresh_token']},
            format='json',
        )

        self.assertEqual(refreshed.status_code, 200)
        claims = jwt.decode(
            refreshed.data['access_token'],
            options={'verify_signature': False},
            algorithms=['HS256'],
        )
        self.assertEqual(claims['user_metadata']['name'], 'Ada Lovelace')

    def test_unauthenticated_rejected(self):
        response = self.client.patch('/api/v1/user', {'name': 'Ada'}, format='json')
        self.assertEqual(response.status_code, 401)


class OAuthLoginKeepsChosenNameTests(TestCase):
    def test_user_chosen_name_survives_github_email_link(self):
        user = User.objects.create_user(username='seb', email='seb@example.com', first_name='Seb')

        linked, created, error, _ = resolve_oauth_user(
            provider='github',
            profile=_github_profile('seb@example.com', 'Sébastien Barbier'),
        )

        self.assertIsNone(error)
        self.assertFalse(created)
        self.assertEqual(linked.pk, user.pk)
        user.refresh_from_db()
        self.assertEqual((user.first_name, user.last_name), ('Seb', ''))

    def test_empty_name_is_filled_from_provider(self):
        user = User.objects.create_user(username='seb', email='seb@example.com')

        resolve_oauth_user(
            provider='github',
            profile=_github_profile('seb@example.com', 'Sébastien Barbier'),
        )

        user.refresh_from_db()
        self.assertEqual((user.first_name, user.last_name), ('Sébastien', 'Barbier'))

    def test_existing_social_link_never_touches_name(self):
        user = User.objects.create_user(username='seb', email='seb@example.com')
        resolve_oauth_user(provider='github', profile=_github_profile('seb@example.com', 'First Name'))
        user.first_name, user.last_name = 'Chosen', ''
        user.save()

        resolve_oauth_user(provider='github', profile=_github_profile('seb@example.com', 'Changed Name'))

        user.refresh_from_db()
        self.assertEqual((user.first_name, user.last_name), ('Chosen', ''))
