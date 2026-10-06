"""Company OAuth settings must fail closed when required base URLs are missing."""

from __future__ import annotations

from allauth.socialaccount.providers.auth0.views import Auth0OAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.okta.views import OktaOAuth2Adapter
from django.test import RequestFactory, TestCase

from allauth.socialaccount.models import SocialApp

from apps.authapi.oauth_adapter_settings import apply_oauth_adapter_settings
from apps.authapi.provider_registry import get_provider_catalog


class OAuthAdapterRequiredSettingsTests(TestCase):
    def setUp(self):
        self.request = RequestFactory().get('/')

    def test_okta_missing_base_url_raises(self):
        entry = get_provider_catalog().by_slug()['okta']
        app = SocialApp(
            provider='okta',
            client_id='okta-client',
            secret='secret',
            settings={'catalog_slug': 'okta'},
        )
        adapter = OktaOAuth2Adapter(self.request)
        with self.assertRaises(OAuth2Error):
            apply_oauth_adapter_settings(adapter, social_app=app, entry=entry)

    def test_auth0_missing_url_raises(self):
        entry = get_provider_catalog().by_slug()['auth0']
        app = SocialApp(
            provider='auth0',
            client_id='auth0-client',
            secret='secret',
            settings={'catalog_slug': 'auth0'},
        )
        adapter = Auth0OAuth2Adapter(self.request)
        with self.assertRaises(OAuth2Error):
            apply_oauth_adapter_settings(adapter, social_app=app, entry=entry)
