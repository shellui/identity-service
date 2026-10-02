"""Twitch OAuth: pinned hosts, Helix uid, verified email, company app uniqueness."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from allauth.socialaccount.models import SocialAccount, SocialApp
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.oauth import build_authorize_url
from apps.authapi.oauth_allauth import split_pkce_authorize_params
from apps.authapi.oauth_state import OAUTH_STATE_NONCE_COOKIE, build_oauth_state, parse_oauth_state
from apps.authapi.oauth_twitch import TWITCH_ACCESS_TOKEN_URL, TWITCH_AUTHORIZE_URL, TWITCH_PROFILE_URL
from apps.authapi.oauth_user import extract_oauth_profile
from apps.authapi.provider_registry import get_provider_catalog, validate_extra_settings
from apps.authapi.tests.oauth_strict_harness import (
    StrictProviderSpec,
    _assert_adapter_hosts,
    _json_handler,
    _token_json_handler,
    strict_provider_http,
)
from apps.authapi.tests.oauth_supported_provider_fixtures import supported_provider_fixture
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect

User = get_user_model()

_TWITCH_SETTINGS = override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
    OAUTH_TOKEN_DELIVERY='code',
    OAUTH_SKIP_CONFIRM_PROVIDERS=['google'],
)


def _helix_handler(payload: dict, *, status: int = 200, capture: dict | None = None):
    def _handler(http):
        if capture is not None:
            capture.setdefault('calls', []).append(
                {
                    'authorization': http.headers.get('Authorization'),
                    'client_id': http.headers.get('Client-Id'),
                    'path': http.path.split('?', 1)[0],
                }
            )
        if status >= 400:
            from apps.authapi.tests.oauth_test_crypto import _drain_request_body

            _drain_request_body(http)
            body = b'{"error":"Unauthorized","status":401,"message":"invalid token"}'
            http.send_response(status)
            http.send_header('Content-Type', 'application/json')
            http.send_header('Content-Length', str(len(body)))
            http.end_headers()
            http.wfile.write(body)
            return
        _json_handler(payload)(http)

    return _handler


def _twitch_spec(*, profile: dict | None, body: dict | None = None, status: int = 200, capture: dict | None = None):
    if body is None:
        body = {'data': [profile or {}]}
    routes = {
        ('id.twitch.tv', 'POST', '/oauth2/token'): _token_json_handler(
            {'access_token': 'twitch-access-token', 'token_type': 'bearer'}
        ),
        ('api.twitch.tv', 'GET', '/helix/users'): _helix_handler(body, status=status, capture=capture),
    }
    expected = ''
    if profile and profile.get('id') is not None:
        expected = str(profile['id'])
    return StrictProviderSpec(
        slug='twitch',
        authorize_netloc='id.twitch.tv',
        routes=routes,
        hostnames=['id.twitch.tv', 'api.twitch.tv'],
        expected_uid=expected,
    )


@_TWITCH_SETTINGS
class TwitchOAuthCallbackTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Twitch Co', slug='twitch-co')
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )
        self.social_app = SocialApp.objects.create(
            provider='twitch',
            name='twitch-co',
            client_id='twitch-client-id',
            secret='twitch-client-secret',
            settings={
                'catalog_slug': 'twitch',
                'authorize_url': 'https://evil.example/oauth/authorize',
                'profile_url': 'https://evil.example/helix/users',
                'scope': ['user:read:email', 'channel:manage:broadcast'],
            },
        )
        self.oauth_client = CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.social_app,
            is_active=True,
        )
        self.fixture = supported_provider_fixture('twitch')

    def _callback(self, spec: StrictProviderSpec):
        redirect_to = 'https://shell.example.com/login/callback'
        state, _nonce = build_oauth_state(
            provider='twitch',
            redirect_to=redirect_to,
            company_id=self.company.id,
            company_oauth_client_id=self.oauth_client.id,
        )
        payload, err = parse_oauth_state(state)
        self.assertIsNone(err)
        assert payload is not None
        with strict_provider_http(spec):
            self.client.cookies[OAUTH_STATE_NONCE_COOKIE] = payload['nonce']
            return self.client.get('/api/v1/oauth/callback', {'code': 'twitch-code', 'state': state})

    def _assert_helix_headers(self, capture: dict):
        calls = capture.get('calls') or []
        self.assertGreaterEqual(len(calls), 1)
        for call in calls:
            self.assertEqual(call['path'], '/helix/users')
            self.assertTrue(str(call['authorization'] or '').startswith('Bearer '))
            self.assertNotIn('access_token', call['path'])
            self.assertEqual(call['client_id'], self.social_app.client_id)

    def test_callback_creates_user_from_helix_id(self):
        capture: dict = {}
        profile = dict(self.fixture.profile_document)
        before = User.objects.count()
        response = self._callback(_twitch_spec(profile=profile, capture=capture))
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn(b'user-twitch@example.com', response.content)
        self.assertEqual(User.objects.count(), before + 1)
        account = SocialAccount.objects.get(provider='twitch', uid='141981764')
        self.assertEqual(account.user.email, 'user-twitch@example.com')
        self.assertNotIn('|', account.uid)
        self.assertEqual(account.user.first_name, 'Twitch')
        self._assert_helix_headers(capture)

    def test_returning_user_matches_uid(self):
        profile = dict(self.fixture.profile_document)
        first = self._callback(_twitch_spec(profile=profile))
        self.assertEqual(first.status_code, 200, first.content)
        created = SocialAccount.objects.get(provider='twitch', uid='141981764').user
        changed = dict(profile)
        changed['email'] = 'other-twitch@example.com'
        changed['display_name'] = 'Renamed'
        before = User.objects.count()
        second = self._callback(_twitch_spec(profile=changed))
        self.assertEqual(second.status_code, 200, second.content)
        self.assertEqual(User.objects.count(), before)
        account = SocialAccount.objects.get(provider='twitch', uid='141981764')
        self.assertEqual(account.user_id, created.id)
        self.assertEqual(SocialAccount.objects.filter(provider='twitch').count(), 1)

    def test_verified_email_links_existing_user(self):
        victim = User.objects.create_user(
            username='twitch-victim',
            email='user-twitch@example.com',
            password='x',
        )
        before = User.objects.count()
        response = self._callback(_twitch_spec(profile=dict(self.fixture.profile_document)))
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(User.objects.count(), before)
        account = SocialAccount.objects.get(provider='twitch', uid='141981764')
        self.assertEqual(account.user_id, victim.id)

    def test_missing_email_returns_oauth_identity_failed(self):
        profile = {
            'id': '141981764',
            'login': 'no-email',
            'display_name': 'No Email',
            'email_verified': True,
        }
        before = User.objects.count()
        response = self._callback(_twitch_spec(profile=profile))
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get('error_code'), 'oauth_identity_failed')
        self.assertEqual(User.objects.count(), before)
        self.assertFalse(SocialAccount.objects.filter(provider='twitch').exists())

    def test_missing_id_returns_token_exchange_failed(self):
        before = User.objects.count()
        response = self._callback(
            _twitch_spec(
                profile=None,
                body={'data': [{'login': 'no-id', 'email': 'noid@example.com'}]},
            )
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get('error_code'), 'token_exchange_failed')
        self.assertEqual(User.objects.count(), before)
        self.assertFalse(SocialAccount.objects.filter(provider='twitch').exists())

    def test_userinfo_failure_returns_token_exchange_failed(self):
        before = User.objects.count()
        response = self._callback(_twitch_spec(profile={'id': '141981764'}, status=401))
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get('error_code'), 'token_exchange_failed')
        self.assertEqual(User.objects.count(), before)
        self.assertFalse(SocialAccount.objects.filter(provider='twitch').exists())


class TwitchProfileExtractionTests(TestCase):
    def test_uid_is_helix_id_and_email_is_trusted_without_email_verified_flag(self):
        entry = get_provider_catalog().by_slug()['twitch']
        app = SocialApp(
            provider='twitch',
            client_id='twitch-client-id',
            secret='twitch-client-secret',
            settings={'catalog_slug': 'twitch'},
        )
        profile, err = extract_oauth_profile(
            'twitch',
            dict(supported_provider_fixture('twitch').profile_document),
            'twitch-access-token',
            catalog_entry=entry,
            social_app=app,
        )
        self.assertIsNone(err)
        assert profile is not None
        self.assertEqual(profile.provider_id, '141981764')
        self.assertEqual(profile.social_uid, '141981764')
        self.assertNotEqual(profile.social_uid, 'decoy-twitch-sub')
        self.assertTrue(profile.email_verified_for_link)
        self.assertEqual(profile.email, 'user-twitch@example.com')
        self.assertEqual(profile.full_name, 'Twitch Fixture')
        self.assertEqual(profile.avatar_url, 'https://static-cdn.example/twitch-fixture.png')

    def test_email_verified_true_without_email_does_not_build_a_profile(self):
        entry = get_provider_catalog().by_slug()['twitch']
        app = SocialApp(provider='twitch', client_id='cid', secret='secret')
        profile, err = extract_oauth_profile(
            'twitch',
            {'id': '141981764', 'email_verified': True},
            'token',
            catalog_entry=entry,
            social_app=app,
        )
        self.assertIsNone(profile)
        self.assertIn('verified email', (err or '').lower())

    def test_missing_id_does_not_build_a_profile(self):
        entry = get_provider_catalog().by_slug()['twitch']
        app = SocialApp(provider='twitch', client_id='cid', secret='secret')
        profile, err = extract_oauth_profile(
            'twitch',
            {'login': 'no-id', 'email': 'noid@example.com'},
            'token',
            catalog_entry=entry,
            social_app=app,
        )
        self.assertIsNone(profile)
        self.assertIn('user id', (err or '').lower())


@_TWITCH_SETTINGS
class TwitchAuthorizeAndCatalogTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Twitch Catalog', slug='twitch-catalog')
        self.owner = User.objects.create_user(
            username='twitch-owner',
            email='twitch-owner@example.com',
            password='x',
        )
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.client.force_authenticate(user=self.owner)
        self.social_app = SocialApp.objects.create(
            provider='twitch',
            name='twitch-authz',
            client_id='twitch-client-id',
            secret='twitch-client-secret',
            settings={
                'catalog_slug': 'twitch',
                'scope': ['user:read:email', 'moderator:read:followers'],
            },
        )
        self.oauth_client = CompanyOAuthClient.objects.create(
            company=self.company,
            social_app=self.social_app,
            is_active=True,
        )

    def test_authorize_url_pins_host_scope_and_state_without_pkce(self):
        request = RequestFactory().get('/api/v1/authorize')
        request.session = {}
        pkce_params, verifier = split_pkce_authorize_params(request, self.social_app)
        self.assertIsNone(verifier)
        self.assertNotIn('code_challenge', pkce_params)
        url = build_authorize_url(
            'twitch',
            redirect_uri='https://auth.example.com/api/v1/oauth/callback',
            state='signed-state-value',
            request=request,
            company_id=self.company.id,
            company_oauth_client_id=self.oauth_client.id,
            pkce_params=pkce_params or None,
        )
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, 'https')
        self.assertEqual(parsed.hostname, 'id.twitch.tv')
        self.assertEqual(parsed.path, '/oauth2/authorize')
        self.assertEqual(query.get('scope'), ['user:read:email'])
        self.assertEqual(query.get('state'), ['signed-state-value'])
        self.assertNotIn('code_challenge', query)
        self.assertNotIn('moderator:read:followers', url)

    def test_adapter_urls_ignore_company_overrides(self):
        self.social_app.settings = {
            'catalog_slug': 'twitch',
            'authorize_url': 'https://evil.example/authorize',
            'access_token_url': 'https://evil.example/token',
            'profile_url': 'https://evil.example/users',
        }
        from allauth.core import context as allauth_context

        from apps.authapi.oauth_adapter_settings import apply_oauth_adapter_settings
        from apps.authapi.oauth_request_context import oauth_allauth_request
        from apps.authapi.oauth_social_account import bind_oauth_social_app
        from allauth.socialaccount.providers import registry

        request = RequestFactory().get('/')
        entry = get_provider_catalog().by_slug()['twitch']
        bind_oauth_social_app(request, self.social_app)
        with oauth_allauth_request(request, social_app=self.social_app), allauth_context.request_context(request):
            provider = registry.get_class('twitch')(request, app=self.social_app)
            adapter = provider.oauth2_adapter_class(request)
            apply_oauth_adapter_settings(adapter, social_app=self.social_app, entry=entry)
            self.assertEqual(adapter.authorize_url, TWITCH_AUTHORIZE_URL)
            self.assertEqual(adapter.access_token_url, TWITCH_ACCESS_TOKEN_URL)
            self.assertEqual(adapter.profile_url, TWITCH_PROFILE_URL)

    def test_assert_adapter_hosts_rejects_off_host_profile(self):
        with self.assertRaises(ValueError) as ctx:
            _assert_adapter_hosts(
                slug='twitch',
                authorize_url=TWITCH_AUTHORIZE_URL,
                access_token_url=TWITCH_ACCESS_TOKEN_URL,
                profile_url='https://evil.example/helix/users',
                company_host=None,
            )
        self.assertIn('profile', str(ctx.exception))
        self.assertIn('evil.example', str(ctx.exception))

    def test_catalog_lists_twitch_supported_with_logo(self):
        response = self.client.get(f'/api/v1/oauth-provider-catalog?company_id={self.company.id}')
        self.assertEqual(response.status_code, 200, response.content)
        twitch = next(item for item in response.data['providers'] if item['docs_slug'] == 'twitch')
        self.assertTrue(twitch['supported'])
        self.assertIsNone(twitch['unsupported_reason'])
        self.assertEqual(twitch['extra_settings_schema'], [])
        self.assertFalse(twitch['multiple_allowed'])
        self.assertEqual(twitch['icon']['source'], 'simple-icons')
        self.assertEqual(twitch['icon']['slug'], 'twitch')
        self.assertEqual(twitch['icon']['hex'], '9146FF')
        self.assertEqual(
            twitch['icon']['svg_url'],
            'https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/twitch.svg',
        )
        self.assertEqual(twitch['console_url'][0]['url'], 'https://dev.twitch.tv/console')
        for field in twitch['extra_settings_schema']:
            self.assertNotIn('label', field)

    def test_validate_extra_settings_rejects_url_override(self):
        entry = get_provider_catalog().by_slug()['twitch']
        _normalized, errors = validate_extra_settings(
            entry,
            {'authorize_url': 'https://evil.example/authorize'},
        )
        self.assertTrue(errors)
        self.assertIn('not allowed', errors[0])


@_TWITCH_SETTINGS
class TwitchCompanyAppApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Twitch API', slug='twitch-api')
        self.owner = User.objects.create_user(
            username='twitch-api-owner',
            email='twitch-api-owner@example.com',
            password='x',
        )
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.client.force_authenticate(user=self.owner)

    def test_create_update_and_duplicate_rejection(self):
        create = self.client.post(
            f'/api/v1/oauth-social-apps?company_id={self.company.id}',
            {
                'docs_slug': 'twitch',
                'client_id': 'twitch-api-client',
                'client_secret': 'twitch-api-secret',
                'extra_settings': {},
            },
            format='json',
        )
        self.assertEqual(create.status_code, 201, create.data)
        app_id = create.data['social_app']['id']
        stored = SocialApp.objects.get(pk=app_id)
        self.assertEqual(stored.provider, 'twitch')
        self.assertEqual(stored.settings.get('catalog_slug'), 'twitch')
        self.assertNotIn('authorize_url', stored.settings)
        self.assertNotIn('scope', stored.settings)

        update = self.client.put(
            f'/api/v1/oauth-social-apps/{app_id}?company_id={self.company.id}',
            {'client_secret': 'twitch-api-secret-rotated'},
            format='json',
        )
        self.assertEqual(update.status_code, 200, update.data)
        stored.refresh_from_db()
        self.assertEqual(stored.secret, 'twitch-api-secret-rotated')

        rejected = self.client.put(
            f'/api/v1/oauth-social-apps/{app_id}?company_id={self.company.id}',
            {'extra_settings': {'profile_url': 'https://evil.example/helix/users'}},
            format='json',
        )
        self.assertEqual(rejected.status_code, 400, rejected.data)
        self.assertEqual(rejected.data.get('error_code'), 'oauth_setting_not_allowed')
        stored.refresh_from_db()
        self.assertNotIn('profile_url', stored.settings)

        duplicate = self.client.post(
            f'/api/v1/oauth-social-apps?company_id={self.company.id}',
            {
                'docs_slug': 'twitch',
                'client_id': 'twitch-api-client-2',
                'client_secret': 'twitch-api-secret-2',
            },
            format='json',
        )
        self.assertEqual(duplicate.status_code, 409, duplicate.data)
        self.assertEqual(duplicate.data.get('error_code'), 'oauth_app_duplicate_provider')
        self.assertEqual(duplicate.data.get('social_app_id'), app_id)
        self.assertNotIn('error', duplicate.data)
        self.assertEqual(CompanyOAuthClient.objects.filter(company=self.company).count(), 1)
