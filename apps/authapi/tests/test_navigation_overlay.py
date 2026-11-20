"""Per-user navigation overlay sync: auth, isolation, schema, and size limits."""

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.models import UserNavigationOverlay
from apps.authapi.navigation_overlay import MAX_INSTALLED_APPS, MAX_PAYLOAD_BYTES
from apps.authapi.views import _issue_personal_access_token, _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

URL = '/api/v1/navigation-overlay'


def _app(index=0, **extra):
    app = {
        'id': f'app{index}',
        'name': f'App {index}',
        'url': f'https://app{index}.example.com/',
        'capabilities': ['theme', 'navigate'],
    }
    app.update(extra)
    return app


def _overlay(**overrides):
    body = {
        'version': 1,
        'installedApps': [_app()],
        'order': ['app0', '/home'],
        'hiddenPaths': ['/archive'],
        'updatedAt': '2026-11-20T02:43:00Z',
    }
    body.update(overrides)
    return body


@override_settings(ALLOWED_HOSTS=['testserver'])
class NavigationOverlayApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.company = Company.objects.create(name='Overlay Co', slug='overlay-co')
        self.other_company = Company.objects.create(name='Other Co', slug='other-co')
        self.user = User.objects.create_user(username='ada', email='ada@example.com', password='secret')
        self.other = User.objects.create_user(username='grace', email='grace@example.com', password='secret')
        set_company_access(self.company, self.user, enabled=True)
        set_company_access(self.company, self.other, enabled=True)
        self.auth = self._bearer(self.user, self.company)
        self.other_auth = self._bearer(self.other, self.company)

    def _bearer(self, user, company):
        tokens = _issue_shellui_tokens(user, company=company)
        return f'Bearer {tokens["access_token"]}'

    def _put(self, body, *, auth=None, query=''):
        return self.client.put(
            URL + query,
            body,
            format='json',
            HTTP_AUTHORIZATION=auth or self.auth,
        )

    def _get(self, *, auth=None, query=''):
        return self.client.get(URL + query, HTTP_AUTHORIZATION=auth or self.auth)

    def _delete(self, *, auth=None, query=''):
        return self.client.delete(URL + query, HTTP_AUTHORIZATION=auth or self.auth)

    def test_unauthenticated_requests_are_rejected(self):
        self.assertEqual(self.client.get(URL).status_code, 401)
        self.assertEqual(self.client.put(URL, _overlay(), format='json').status_code, 401)
        self.assertEqual(self.client.delete(URL).status_code, 401)
        self.assertEqual(
            self.client.get(URL, HTTP_AUTHORIZATION='Bearer not-a-token').status_code,
            401,
        )
        self.assertFalse(UserNavigationOverlay.objects.exists())

    def test_get_is_null_until_a_document_is_saved(self):
        response = self._get()

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)
        self.assertEqual(response.content, b'null')

    def test_put_get_delete_round_trip(self):
        saved = _overlay(
            installedApps=[
                _app(
                    path='notes',
                    iconUrl='https://cdn.example.com/notes.png',
                    capabilities=['theme', 'locale', 'ui', 'navigate', 'storage', 'ai'],
                )
            ]
        )

        created = self._put(saved)
        self.assertEqual(created.status_code, 200, created.data)
        self.assertEqual(created.data, saved)

        fetched = self._get()
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.data, saved)
        self.assertEqual(UserNavigationOverlay.objects.get(user=self.user).document, saved)

        deleted = self._delete()
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(deleted.content, b'')
        self.assertFalse(UserNavigationOverlay.objects.filter(user=self.user).exists())

        again = self._get()
        self.assertEqual(again.content, b'null')
        self.assertEqual(self._delete().status_code, 204)

    def test_users_cannot_read_or_write_each_others_overlay(self):
        ada_doc = _overlay(hiddenPaths=['/ada'])
        grace_doc = _overlay(hiddenPaths=['/grace'], installedApps=[_app(index=1)], order=['app1'])
        self.assertEqual(self._put(ada_doc).status_code, 200)
        self.assertEqual(self._put(grace_doc, auth=self.other_auth).status_code, 200)

        self.assertEqual(self._get().data['hiddenPaths'], ['/ada'])
        self.assertEqual(self._get(auth=self.other_auth).data['hiddenPaths'], ['/grace'])

        stolen = self._get(auth=self.other_auth, query=f'?user_id={self.user.pk}')
        self.assertEqual(stolen.status_code, 403)
        self.assertEqual(stolen.data['error'], 'Forbidden.')

        overwritten = self._put(
            {**ada_doc, 'user_id': self.user.pk, 'hiddenPaths': ['/pwned']},
            auth=self.other_auth,
        )
        self.assertEqual(overwritten.status_code, 403)
        self.assertEqual(self._get().data['hiddenPaths'], ['/ada'])

        cleared = self._delete(auth=self.other_auth, query=f'?userId={self.user.pk}')
        self.assertEqual(cleared.status_code, 403)
        self.assertTrue(UserNavigationOverlay.objects.filter(user=self.user).exists())

        self.assertEqual(self._delete(auth=self.other_auth).status_code, 204)
        self.assertTrue(UserNavigationOverlay.objects.filter(user=self.user).exists())
        self.assertFalse(UserNavigationOverlay.objects.filter(user=self.other).exists())

    def test_same_account_is_shared_across_companies_it_belongs_to(self):
        set_company_access(self.other_company, self.user, enabled=True)
        other_company_auth = self._bearer(self.user, self.other_company)
        document = _overlay()
        self.assertEqual(self._put(document).status_code, 200)

        fetched = self._get(auth=other_company_auth)
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.data, document)
        self.assertEqual(UserNavigationOverlay.objects.filter(user=self.user).count(), 1)

    def test_company_scope_matches_preferences(self):
        mismatch = self._get(query=f'?company_id={self.other_company.id}')
        self.assertEqual(mismatch.status_code, 403)
        self.assertEqual(mismatch.data['error'], 'Requested company_id does not match token company_id.')

        outsider = Company.objects.create(name='Outsider', slug='outsider')
        outsider_auth = self._bearer(self.user, outsider)
        forbidden = self._get(auth=outsider_auth)
        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(forbidden.data['error'], 'Forbidden for this company.')
        self.assertFalse(UserNavigationOverlay.objects.exists())

    def test_read_only_personal_access_token_cannot_write(self):
        _row, secret = _issue_personal_access_token(
            self.user,
            self.company,
            read_only=True,
            name='overlay-read',
        )
        header = f'Bearer {secret}'

        self.assertEqual(self._get(auth=header).status_code, 200)
        self.assertEqual(self._put(_overlay(), auth=header).status_code, 403)
        self.assertEqual(self._delete(auth=header).status_code, 403)
        self.assertFalse(UserNavigationOverlay.objects.exists())

    def test_schema_rejections_do_not_replace_a_saved_document(self):
        self.assertEqual(self._put(_overlay()).status_code, 200)
        cases = [
            ('version string', _overlay(version='1'), 'version'),
            ('version bool', _overlay(version=True), 'version'),
            ('version two', _overlay(version=2), 'version'),
            ('missing updatedAt', {key: value for key, value in _overlay().items() if key != 'updatedAt'}, 'updatedAt'),
            ('installedApps object', _overlay(installedApps={'id': 'app0'}), 'installedApps'),
            ('order string', _overlay(order='app0'), 'order'),
            ('hiddenPaths null', _overlay(hiddenPaths=None), 'hiddenPaths'),
            ('naive timestamp', _overlay(updatedAt='2026-11-20T02:43:00'), 'timezone'),
            ('unknown field', {**_overlay(), 'script': 'alert(1)'}, 'Unknown field'),
            ('not an object', ['nope'], 'JSON object'),
            ('http url', _overlay(installedApps=[_app(url='http://app0.example.com/')]), 'https'),
            (
                'javascript url',
                _overlay(installedApps=[_app(url='javascript:alert(1)')]),
                'https',
            ),
            (
                'url credentials',
                _overlay(installedApps=[_app(url='https://user:secret@app0.example.com/')]),
                'password',
            ),
            (
                'third-party auth',
                _overlay(installedApps=[_app(capabilities=['theme', 'auth'])]),
                'auth',
            ),
            (
                'explicit third-party auth',
                _overlay(installedApps=[_app(firstParty=False, capabilities=['auth'])]),
                'auth',
            ),
            (
                'unknown capability',
                _overlay(installedApps=[_app(capabilities=['billing'])]),
                'billing',
            ),
            (
                'first-party unknown capability',
                _overlay(installedApps=[_app(firstParty=True, capabilities=['auth', 'billing'])]),
                'billing',
            ),
            (
                'duplicate capability',
                _overlay(installedApps=[_app(capabilities=['theme', 'theme'])]),
                'duplicate',
            ),
        ]
        for label, body, needle in cases:
            with self.subTest(label=label):
                response = self._put(body)
                self.assertEqual(response.status_code, 400, response.data)
                self.assertIn(needle, response.data['error'])
                self.assertEqual(self._get().data['hiddenPaths'], ['/archive'])

    def test_first_party_auth_capability_is_saved(self):
        document = _overlay(
            installedApps=[_app(firstParty=True, capabilities=['theme', 'storage', 'auth'])]
        )

        response = self._put(document)

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['installedApps'][0]['capabilities'], ['theme', 'storage', 'auth'])
        self.assertIs(response.data['installedApps'][0]['firstParty'], True)

    def test_rejects_more_than_100_installed_apps(self):
        apps = [_app(index) for index in range(MAX_INSTALLED_APPS + 1)]
        response = self._put(_overlay(installedApps=apps, order=[]))

        self.assertEqual(response.status_code, 400, response.data)
        self.assertIn('100', response.data['error'])
        self.assertFalse(UserNavigationOverlay.objects.exists())

        accepted = self._put(
            _overlay(installedApps=[_app(index) for index in range(MAX_INSTALLED_APPS)], order=[])
        )
        self.assertEqual(accepted.status_code, 200, accepted.data)
        self.assertEqual(len(accepted.data['installedApps']), MAX_INSTALLED_APPS)

    def test_rejects_payload_over_64_kb_without_replacing_the_saved_document(self):
        self.assertEqual(self._put(_overlay()).status_code, 200)
        raw = b'{"version":1,"pad":"' + (b'a' * MAX_PAYLOAD_BYTES) + b'"}'
        self.assertGreater(len(raw), MAX_PAYLOAD_BYTES)

        response = self.client.put(
            URL,
            data=raw,
            content_type='application/json',
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn('64 KB', response.json()['error'])
        self.assertEqual(self._get().data['hiddenPaths'], ['/archive'])

    def test_deleting_the_account_removes_the_overlay(self):
        self.assertEqual(self._put(_overlay()).status_code, 200)
        self.user.delete()
        self.assertFalse(UserNavigationOverlay.objects.exists())

    @override_settings(CORS_ALLOW_ALL_ORIGINS=True, CORS_ALLOW_CREDENTIALS=False)
    def test_cors_matches_other_bearer_endpoints(self):
        origin = 'https://shell.example.com'
        preflight = self.client.options(
            URL,
            HTTP_ORIGIN=origin,
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='PUT',
            HTTP_ACCESS_CONTROL_REQUEST_HEADERS='authorization,content-type',
        )
        self.assertEqual(preflight.status_code, 200)
        self.assertEqual(preflight['Access-Control-Allow-Origin'], '*')
        self.assertIn('PUT', preflight['Access-Control-Allow-Methods'])
        self.assertIn('DELETE', preflight['Access-Control-Allow-Methods'])

        fetched = self.client.get(
            URL,
            HTTP_AUTHORIZATION=self.auth,
            HTTP_ORIGIN=origin,
        )
        self.assertEqual(fetched['Access-Control-Allow-Origin'], '*')
