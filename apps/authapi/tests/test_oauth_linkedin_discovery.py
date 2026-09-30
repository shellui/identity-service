"""Production LinkedIn OIDC discovery must stay on pinned hosts."""

from __future__ import annotations

from unittest.mock import patch

from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from django.test import RequestFactory, TestCase

from apps.authapi.oauth_adapter_settings import prefetch_openid_connect_config
from apps.authapi.oauth_linkedin import (
    LINKEDIN_ISSUER,
    LINKEDIN_JWKS_HOST,
    LINKEDIN_TOKEN_HOST,
    LINKEDIN_USERINFO_HOST,
    assert_linkedin_oidc_discovery_hosts,
)
from apps.authapi.provider_registry import get_provider_catalog
from allauth.socialaccount.providers.openid_connect.views import OpenIDConnectOAuth2Adapter


class LinkedInDiscoveryHostTests(TestCase):
    def test_assert_linkedin_oidc_discovery_hosts_rejects_evil_token_endpoint(self):
        document = {
            'issuer': LINKEDIN_ISSUER,
            'authorization_endpoint': f'https://{LINKEDIN_TOKEN_HOST}/oauth/v2/authorization',
            'token_endpoint': 'https://example.com/oauth/v2/accessToken',
            'userinfo_endpoint': f'https://{LINKEDIN_USERINFO_HOST}/v2/userinfo',
            'jwks_uri': f'https://{LINKEDIN_JWKS_HOST}/oauth/openid/jwks',
        }
        with self.assertRaises(OAuth2Error):
            assert_linkedin_oidc_discovery_hosts(document)

    def test_prefetch_openid_connect_config_rejects_malicious_discovery(self):
        request = RequestFactory().get('/')
        entry = get_provider_catalog().by_slug()['linkedin']
        app = SocialApp.objects.create(
            provider='openid_connect',
            provider_id='linkedin',
            name='linkedin-discovery-test',
            client_id='li-disc',
            secret='secret',
            settings={'catalog_slug': 'linkedin', 'server_url': 'https://www.linkedin.com/oauth'},
        )
        adapter = OpenIDConnectOAuth2Adapter(request, 'linkedin')
        evil = {
            'issuer': LINKEDIN_ISSUER,
            'authorization_endpoint': f'https://{LINKEDIN_TOKEN_HOST}/oauth/v2/authorization',
            'token_endpoint': f'https://{LINKEDIN_TOKEN_HOST}/oauth/v2/accessToken',
            'userinfo_endpoint': 'https://example.com/v2/userinfo',
            'jwks_uri': f'https://{LINKEDIN_JWKS_HOST}/oauth/openid/jwks',
        }
        with patch('apps.authapi.oauth_adapter_settings.safe_get_json', return_value=evil):
            with self.assertRaises(OAuth2Error):
                prefetch_openid_connect_config(adapter, entry=entry)
