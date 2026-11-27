"""Per-user, per-company navigation overlay: auth, isolation, schema, and size limits."""

from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.models import EventLog
from apps.agents.models import Agent
from apps.agents.tokens import encode_access_token
from apps.authapi.account_lifecycle import remove_user_from_company
from apps.authapi.models import UserNavigationOverlay
from apps.authapi.navigation_overlay import MAX_INSTALLED_APPS, MAX_PAYLOAD_BYTES
from apps.authapi.views import _issue_personal_access_token, _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

URL = '/api/v1/navigation-overlay'
INSTALLED_AT = '2026-11-20T02:43:00.000Z'
SCHEMA_DIR = Path(__file__).resolve().parents[1] / 'schemas'
EXAMPLE_PATH = SCHEMA_DIR / 'shell-navigation-overlay.v1.example.json'


def _app(index=0, **extra):
    app = {
        'id': f'app{index}',
        'name': f'App {index}',
        'origin': f'https://app{index}.example.com',
        'url': f'https://app{index}.example.com/',
        'path': f'app{index}',
        'thirdParty': True,
        'capabilities': ['theme', 'navigate'],
        'installedAt': INSTALLED_AT,
        'updatedAt': INSTALLED_AT,
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

    def _put(self, body, *, auth=None, query='', if_match=None):
        headers = {'HTTP_AUTHORIZATION': auth or self.auth}
        if if_match is not None:
            headers['HTTP_IF_MATCH'] = if_match
        return self.client.put(URL + query, body, format='json', **headers)

    def _get(self, *, auth=None, query=''):
        return self.client.get(URL + query, HTTP_AUTHORIZATION=auth or self.auth)

    def _delete(self, *, auth=None, query='', if_match=None):
        headers = {'HTTP_AUTHORIZATION': auth or self.auth}
        if if_match is not None:
            headers['HTTP_IF_MATCH'] = if_match
        return self.client.delete(URL + query, **headers)

    def _etag(self, response):
        return response.headers.get('ETag') or response.get('ETag')

    def test_unauthenticated_requests_are_rejected(self):
        self.assertEqual(self.client.get(URL).status_code, 401)
        self.assertEqual(self.client.put(URL, _overlay(), format='json').status_code, 401)
        self.assertEqual(self.client.delete(URL).status_code, 401)

    def test_get_is_null_until_a_document_is_saved(self):
        response = self._get()
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)
        self.assertEqual(response.content, b'null')

    def test_put_get_delete_round_trip(self):
        document = _overlay()
        created = self._put(document)
        self.assertEqual(created.status_code, 200, created.data)
        self.assertEqual(created.data['version'], 1)
        self.assertEqual(created.data['installedApps'][0]['id'], 'app0')
        self.assertIs(created.data['installedApps'][0]['thirdParty'], True)
        self.assertEqual(created.data['installedApps'][0]['origin'], 'https://app0.example.com')
        self.assertTrue(created.data['updatedAt'].endswith('Z') or '+' in created.data['updatedAt'])
        etag = self._etag(created)
        self.assertTrue(etag)

        fetched = self._get()
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.data['installedApps'], created.data['installedApps'])
        self.assertEqual(self._etag(fetched), etag)

        deleted = self._delete(if_match=etag)
        self.assertEqual(deleted.status_code, 204)
        self.assertFalse(UserNavigationOverlay.objects.exists())
        self.assertIsNone(self._get().data)

    def test_users_cannot_read_or_write_each_others_overlay(self):
        created = self._put(_overlay())
        self.assertEqual(created.status_code, 200)
        etag = self._etag(created)

        self.assertIsNone(self._get(auth=self.other_auth).data)
        self.assertEqual(self._delete(auth=self.other_auth, if_match='*').status_code, 204)
        self.assertTrue(UserNavigationOverlay.objects.filter(user=self.user).exists())
        self.assertFalse(UserNavigationOverlay.objects.filter(user=self.other).exists())

        other_created = self._put(_overlay(hiddenPaths=['/other']), auth=self.other_auth)
        self.assertEqual(other_created.status_code, 200)
        self.assertEqual(self._get().data['hiddenPaths'], ['/archive'])
        self.assertEqual(self._get(auth=self.other_auth).data['hiddenPaths'], ['/other'])

        self.assertEqual(self._delete(if_match=etag).status_code, 204)
        self.assertFalse(UserNavigationOverlay.objects.filter(user=self.user).exists())
        self.assertTrue(UserNavigationOverlay.objects.filter(user=self.other).exists())

    def test_overlays_are_isolated_per_company(self):
        set_company_access(self.other_company, self.user, enabled=True)
        other_company_auth = self._bearer(self.user, self.other_company)
        created = self._put(_overlay())
        self.assertEqual(created.status_code, 200)

        fetched = self._get(auth=other_company_auth)
        self.assertEqual(fetched.status_code, 200)
        self.assertIsNone(fetched.data)
        self.assertEqual(UserNavigationOverlay.objects.filter(user=self.user).count(), 1)

        other = self._put(_overlay(hiddenPaths=['/other-co']), auth=other_company_auth)
        self.assertEqual(other.status_code, 200)
        self.assertEqual(self._get().data['hiddenPaths'], ['/archive'])
        self.assertEqual(self._get(auth=other_company_auth).data['hiddenPaths'], ['/other-co'])
        self.assertEqual(UserNavigationOverlay.objects.filter(user=self.user).count(), 2)

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

    def test_disabled_members_cannot_read_or_write(self):
        set_company_access(self.company, self.user, enabled=False)
        self.assertEqual(self._get().status_code, 403)
        self.assertEqual(self._put(_overlay()).status_code, 403)
        self.assertEqual(self._delete(if_match='*').status_code, 403)

    def test_read_only_and_write_personal_access_tokens_cannot_write(self):
        for read_only, name in ((True, 'overlay-read'), (False, 'overlay-write')):
            with self.subTest(read_only=read_only):
                _row, secret = _issue_personal_access_token(
                    self.user,
                    self.company,
                    read_only=read_only,
                    name=name,
                )
                header = f'Bearer {secret}'
                self.assertEqual(self._get(auth=header).status_code, 200)
                put = self._put(_overlay(), auth=header)
                self.assertEqual(put.status_code, 403)
                # Read-only PATs may be refused by the shared permission class
                # before this view runs; write PATs reach the overlay-specific code.
                if not read_only:
                    self.assertEqual(put.data.get('error_code'), 'pat_cannot_edit_navigation')
                self.assertEqual(self._delete(auth=header, if_match='*').status_code, 403)
                self.assertFalse(UserNavigationOverlay.objects.exists())

    def test_agent_tokens_cannot_read_or_write(self):
        agent = Agent.objects.create(
            company=self.company,
            name='Overlay Agent',
            created_by=self.user,
            services_allowed=['identity'],
        )
        header = f'Bearer {encode_access_token(agent, resource="https://identity.test/mcp")}'
        for method in (self._get, lambda **kw: self._put(_overlay(), **kw), lambda **kw: self._delete(if_match='*', **kw)):
            response = method(auth=header)
            # Authentication already refuses an agent token outside /mcp (401). The view also
            # refuses one (403) as a second line of defense.
            self.assertIn(response.status_code, (401, 403), response.data)
            if response.status_code == 403:
                self.assertEqual(response.data['error_code'], 'agent_cannot_edit_navigation')
        self.assertFalse(UserNavigationOverlay.objects.exists())

    def test_schema_rejections_do_not_replace_a_saved_document(self):
        created = self._put(_overlay())
        self.assertEqual(created.status_code, 200)
        cases = [
            ('version string', _overlay(version='1'), 'version'),
            ('version bool', _overlay(version=True), 'version'),
            ('version two', _overlay(version=2), 'version'),
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
                'loopback url',
                _overlay(installedApps=[_app(origin='https://127.0.0.1', url='https://127.0.0.1/app')]),
                'loopback',
            ),
            (
                'private ip url',
                _overlay(installedApps=[_app(origin='https://10.0.0.5', url='https://10.0.0.5/app')]),
                'private',
            ),
            (
                'localhost url',
                _overlay(installedApps=[_app(origin='https://localhost', url='https://localhost/app')]),
                'loopback',
            ),
            (
                'auth capability',
                _overlay(installedApps=[_app(capabilities=['theme', 'auth'])]),
                'auth',
            ),
            (
                'firstParty field',
                _overlay(installedApps=[_app(firstParty=True, capabilities=['theme'])]),
                'firstParty',
            ),
            (
                'thirdParty false',
                _overlay(installedApps=[_app(thirdParty=False)]),
                'thirdParty',
            ),
            (
                'unknown capability',
                _overlay(installedApps=[_app(capabilities=['billing'])]),
                'billing',
            ),
            (
                'duplicate capability',
                _overlay(installedApps=[_app(capabilities=['theme', 'theme'])]),
                'duplicate',
            ),
            (
                'missing path',
                _overlay(installedApps=[{k: v for k, v in _app().items() if k != 'path'}]),
                'path',
            ),
            (
                'origin mismatch',
                _overlay(installedApps=[_app(origin='https://other.example.com')]),
                'origin',
            ),
            (
                'reserved path admin',
                _overlay(installedApps=[_app(path='admin')]),
                'reserved',
            ),
            (
                'reserved path files',
                _overlay(installedApps=[_app(path='/files/inbox')]),
                'reserved',
            ),
            (
                'reserved path legal',
                _overlay(installedApps=[_app(path='legal/terms')]),
                'reserved',
            ),
            (
                'hidden reserved path',
                _overlay(hiddenPaths=['/admin']),
                'reserved',
            ),
            (
                'iconUrl alias',
                _overlay(installedApps=[_app(iconUrl='https://app0.example.com/icon.svg')]),
                'iconUrl',
            ),
        ]
        for label, body, needle in cases:
            with self.subTest(label=label):
                response = self._put(body)
                self.assertEqual(response.status_code, 400, response.data)
                self.assertIn(needle, response.data['error'])
                self.assertEqual(self._get().data['hiddenPaths'], ['/archive'])

    def test_auth_capability_is_rejected_even_when_marked_first_party(self):
        document = _overlay(
            installedApps=[_app(firstParty=True, capabilities=['theme', 'storage', 'auth'])]
        )
        response = self._put(document)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertIn('firstParty', response.data['error'])
        self.assertFalse(UserNavigationOverlay.objects.exists())

    def test_accepts_the_shared_shell_contract_fixture(self):
        import json

        document = json.loads(EXAMPLE_PATH.read_text())
        response = self._put(document)
        self.assertEqual(response.status_code, 200, response.data)
        app = response.data['installedApps'][0]
        self.assertEqual(app['id'], 'notes')
        self.assertEqual(app['origin'], 'https://notes.example.com')
        self.assertEqual(app['path'], 'notes')
        self.assertEqual(app['icon'], 'https://notes.example.com/icon.svg')
        self.assertIs(app['thirdParty'], True)
        self.assertEqual(app['installedAt'], '2026-11-20T02:43:00.000Z')
        self.assertNotIn('firstParty', app)
        self.assertNotIn('auth', app['capabilities'])

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
        created = self._put(_overlay())
        self.assertEqual(created.status_code, 200)
        raw = b'{"version":1,"pad":"' + (b'a' * MAX_PAYLOAD_BYTES) + b'"}'
        self.assertGreater(len(raw), MAX_PAYLOAD_BYTES)

        response = self.client.put(
            URL,
            data=raw,
            content_type='application/json',
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(response.status_code, 413, response.content)
        self.assertIn('64 KB', response.json()['error'])
        self.assertEqual(self._get().data['hiddenPaths'], ['/archive'])

    def test_if_match_is_required_once_a_document_exists(self):
        created = self._put(_overlay())
        self.assertEqual(created.status_code, 200)
        etag = self._etag(created)

        missing = self._put(_overlay(hiddenPaths=['/later']))
        self.assertEqual(missing.status_code, 412)
        wrong = self._put(_overlay(hiddenPaths=['/later']), if_match='"not-the-etag"')
        self.assertEqual(wrong.status_code, 412)
        self.assertEqual(self._get().data['hiddenPaths'], ['/archive'])

        updated = self._put(_overlay(hiddenPaths=['/later']), if_match=etag)
        self.assertEqual(updated.status_code, 200, updated.data)
        self.assertEqual(updated.data['hiddenPaths'], ['/later'])
        new_etag = self._etag(updated)
        self.assertTrue(new_etag)
        self.assertNotEqual(new_etag, etag)

        stale_delete = self._delete(if_match=etag)
        self.assertEqual(stale_delete.status_code, 412)
        self.assertTrue(UserNavigationOverlay.objects.exists())
        self.assertEqual(self._delete(if_match=new_etag).status_code, 204)

    def test_writes_are_recorded_in_the_event_log(self):
        created = self._put(_overlay())
        self.assertEqual(created.status_code, 200)
        updated = EventLog.objects.filter(
            event_type='identity.navigation_overlay.updated',
            company=self.company,
            user=self.user,
        )
        self.assertEqual(updated.count(), 1)
        self.assertEqual(updated.get().data.get('app_ids'), ['app0'])

        deleted = self._delete(if_match=self._etag(created))
        self.assertEqual(deleted.status_code, 204)
        self.assertTrue(
            EventLog.objects.filter(
                event_type='identity.navigation_overlay.deleted',
                company=self.company,
                user=self.user,
            ).exists()
        )

    def test_leaving_a_company_deletes_only_that_company_overlay(self):
        set_company_access(self.other_company, self.user, enabled=True)
        self.assertEqual(self._put(_overlay()).status_code, 200)
        other_auth = self._bearer(self.user, self.other_company)
        self.assertEqual(self._put(_overlay(hiddenPaths=['/keep']), auth=other_auth).status_code, 200)
        self.assertEqual(UserNavigationOverlay.objects.filter(user=self.user).count(), 2)

        remove_user_from_company(self.user, self.company, source='test')

        self.assertFalse(UserNavigationOverlay.objects.filter(user=self.user, company=self.company).exists())
        remaining = UserNavigationOverlay.objects.get(user=self.user, company=self.other_company)
        self.assertEqual(remaining.document['hiddenPaths'], ['/keep'])

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

    @override_settings(
        AUTH_RATE_LIMIT_ENABLED=True,
        AUTH_RATE_LIMITS={'navigation_overlay_write': {'limit': 2, 'window': 60}},
    )
    def test_writes_are_rate_limited(self):
        first = self._put(_overlay())
        self.assertEqual(first.status_code, 200, first.data)
        second = self._put(_overlay(hiddenPaths=['/two']), if_match=self._etag(first))
        self.assertEqual(second.status_code, 200, second.data)
        third = self._put(_overlay(hiddenPaths=['/three']), if_match=self._etag(second))
        self.assertEqual(third.status_code, 429)
        self.assertEqual(self._delete(if_match=self._etag(second)).status_code, 429)
