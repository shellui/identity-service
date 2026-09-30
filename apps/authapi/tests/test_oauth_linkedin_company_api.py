"""LinkedIn OAuth apps must be creatable via the company admin API (pinned endpoints)."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.oauth_linkedin import LINKEDIN_OIDC_SERVER_URL
from apps.authapi.oauth_state import OAUTH_STATE_NONCE_COOKIE, build_oauth_state, parse_oauth_state
from apps.authapi.provider_registry import validate_extra_settings
from apps.authapi.tests.oauth_supported_provider_fixtures import supported_provider_fixture
from apps.authapi.tests.oauth_strict_harness import (
    _build_linkedin_strict_spec,
    strict_provider_http,
)
from apps.authapi.tests.oauth_test_crypto import generate_oauth_test_signing_key
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect
from apps.companies.access import set_company_access

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
    OAUTH_TOKEN_DELIVERY='code',
    OAUTH_SKIP_CONFIRM_PROVIDERS=['linkedin'],
)
class LinkedInCompanyOAuthApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='LinkedIn API Co', slug='linkedin-api-co')
        self.owner = User.objects.create_user(username='li-owner', email='owner-li@example.com', password='x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=True)
        self.client.force_authenticate(user=self.owner)
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )

    def test_validate_extra_settings_ignores_client_server_url(self):
        entry = __import__(
            'apps.authapi.provider_registry',
            fromlist=['get_provider_catalog'],
        ).get_provider_catalog().by_slug()['linkedin']
        normalized, errors = validate_extra_settings(
            entry,
            {'server_url': 'https://example.com/oauth'},
        )
        self.assertEqual(errors, [])
        self.assertEqual(normalized['server_url'], LINKEDIN_OIDC_SERVER_URL)

    def test_create_linkedin_social_app_without_server_url(self):
        response = self.client.post(
            f'/api/v1/oauth-social-apps?company_id={self.company.id}',
            {
                'docs_slug': 'linkedin',
                'client_id': 'linkedin-api-client',
                'client_secret': 'linkedin-api-secret',
                'extra_settings': {},
            },
            format='json',
        )
        self.assertEqual(response.status_code, 201, response.data)
        app_id = response.data['social_app']['id']
        app_settings = response.data['social_app']['extra_settings']
        self.assertEqual(app_settings.get('server_url'), LINKEDIN_OIDC_SERVER_URL)
        from allauth.socialaccount.models import SocialApp

        stored = SocialApp.objects.get(pk=app_id).settings
        self.assertEqual(stored.get('catalog_slug'), 'linkedin')

        patch = self.client.put(
            f'/api/v1/oauth-social-apps/{app_id}?company_id={self.company.id}',
            {
                'client_secret': 'linkedin-api-secret-rotated',
                'extra_settings': {'server_url': 'https://attacker.example/oauth'},
            },
            format='json',
        )
        self.assertEqual(patch.status_code, 200, patch.data)
        self.assertEqual(
            patch.data['extra_settings'].get('server_url'),
            LINKEDIN_OIDC_SERVER_URL,
        )

    def test_login_after_api_create_linkedin_app(self):
        create = self.client.post(
            f'/api/v1/oauth-social-apps?company_id={self.company.id}',
            {
                'docs_slug': 'linkedin',
                'client_id': 'linkedin-login-client',
                'client_secret': 'linkedin-login-secret',
            },
            format='json',
        )
        self.assertEqual(create.status_code, 201, create.data)
        app_id = create.data['social_app']['id']
        oauth_client = CompanyOAuthClient.objects.get(company=self.company, social_app_id=app_id)
        social_app = oauth_client.social_app

        fixture = supported_provider_fixture('linkedin')
        signing = generate_oauth_test_signing_key(kid='linkedin-api-kid')
        profile = dict(fixture.profile_document)
        spec = _build_linkedin_strict_spec(
            social_app=social_app,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            signing=signing,
        )
        redirect_to = 'https://shell.example.com/login/callback'
        state, _nonce = build_oauth_state(
            provider='linkedin',
            redirect_to=redirect_to,
            company_id=self.company.id,
            company_oauth_client_id=oauth_client.id,
        )
        payload, err = parse_oauth_state(state)
        self.assertIsNone(err)
        assert payload is not None

        api = APIClient()
        with strict_provider_http(spec):
            api.cookies[OAUTH_STATE_NONCE_COOKIE] = payload['nonce']
            response = api.get('/api/v1/oauth/callback', {'code': 'oidc-code', 'state': state})
        self.assertEqual(response.status_code, 302, response.content)
