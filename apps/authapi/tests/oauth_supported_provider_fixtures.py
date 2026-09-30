"""Hand-written OAuth profile documents for supported identity-hosted OAuth providers.

Expected uids are literal constants (never derived from extract_uid in tests).
Profile shapes follow each provider's API / allauth adapter field names.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from apps.authapi.oauth_linkedin import LINKEDIN_OIDC_SERVER_URL
from apps.authapi.tests.oauth_oidc_strict_fixtures import (
    company_auth0_base,
    company_generic_oidc,
    company_keycloak_oidc,
    company_okta_base,
)

# Providers with passing strict adapter harness tests (see tools/audit_oauth_strict_coverage.py).
RELEASE_SUPPORTED_OAUTH_SLUGS: frozenset[str] = frozenset(
    {
        'apple',
        'auth0',
        'github',
        'gitlab',
        'google',
        'keycloak',
        'line',
        'linkedin',
        'microsoft',
        'okta',
        'openid_connect',
        'reddit',
        'shopify',
        'slack',
    }
)


@dataclass(frozen=True)
class SupportedProviderFixture:
    slug: str
    expected_uid: str
    profile_document: dict[str, Any]
    fixture_source: str
    company_settings_host: str | None = None


def company_gitlab_url(company_slug: str) -> str:
    return f'https://gitlab.{company_slug}.example.com'


def extra_settings_for_supported(slug: str, *, company_slug: str) -> dict[str, Any]:
    if slug == 'gitlab':
        return {'catalog_slug': 'gitlab', 'gitlab_url': company_gitlab_url(company_slug)}
    if slug == 'microsoft':
        return {
            'catalog_slug': 'microsoft',
            'tenant': '11111111-1111-1111-1111-111111111111',
        }
    if slug == 'linkedin':
        return {'catalog_slug': 'linkedin', 'server_url': LINKEDIN_OIDC_SERVER_URL}
    if slug == 'keycloak':
        oidc = company_keycloak_oidc(company_slug)
        return {'catalog_slug': 'keycloak', 'server_url': oidc.server_url}
    if slug == 'openid_connect':
        oidc = company_generic_oidc(company_slug)
        return {'catalog_slug': 'openid_connect', 'server_url': oidc.server_url}
    if slug == 'okta':
        return {'catalog_slug': 'okta', 'OKTA_BASE_URL': company_okta_base(company_slug)}
    if slug == 'auth0':
        return {'catalog_slug': 'auth0', 'AUTH0_URL': company_auth0_base(company_slug)}
    if slug in RELEASE_SUPPORTED_OAUTH_SLUGS:
        return {'catalog_slug': slug}
    return {}


def supported_provider_fixture(slug: str) -> SupportedProviderFixture:
    fixture = _FIXTURES.get(slug)
    if fixture is None:
        raise KeyError(f'No hand-written fixture for provider {slug!r}')
    return fixture


# Profile bodies modeled on provider API responses (allauth extract_uid field names).
_FIXTURES: dict[str, SupportedProviderFixture] = {
    'apple': SupportedProviderFixture(
        slug='apple',
        expected_uid='apple-sub-001',
        profile_document={
            'sub': 'apple-sub-001',
            'email': 'user-apple@example.com',
        },
        fixture_source='Apple Sign In id_token / user payload (sub claim)',
    ),
    'github': SupportedProviderFixture(
        slug='github',
        expected_uid='12345',
        profile_document={
            'id': 12345,
            'login': 'github-fixture-user',
            'name': 'GitHub Fixture User',
            'email': 'user-github@example.com',
        },
        fixture_source='GitHub GET /user (id field per allauth GitHubProvider.extract_uid)',
    ),
    'gitlab': SupportedProviderFixture(
        slug='gitlab',
        expected_uid='4242',
        profile_document={
            'id': 4242,
            'username': 'gitlab-fixture-user',
            'email': 'user-gitlab@example.com',
            'name': 'GitLab Fixture User',
        },
        fixture_source='GitLab GET /api/v4/user (id field per allauth GitLabProvider.extract_uid)',
        company_settings_host='gitlab',  # hostname prefix; full host built per company slug
    ),
    'google': SupportedProviderFixture(
        slug='google',
        expected_uid='google-sub-001',
        profile_document={
            'sub': 'google-sub-001',
            'email': 'user-google@example.com',
            'email_verified': True,
            'name': 'Google Fixture User',
        },
        fixture_source='Google OpenID Connect id_token / userinfo (sub claim)',
    ),
    'line': SupportedProviderFixture(
        slug='line',
        expected_uid='U-line-fixture-001',
        profile_document={
            'userId': 'U-line-fixture-001',
            'displayName': 'Line Fixture User',
        },
        fixture_source='LINE GET /v2/profile (userId per allauth LineProvider.extract_uid)',
    ),
    'microsoft': SupportedProviderFixture(
        slug='microsoft',
        expected_uid='ms-graph-id-001',
        profile_document={
            'id': 'ms-graph-id-001',
            'mail': 'user-ms@contoso.com',
            'userPrincipalName': 'user-ms@contoso.com',
        },
        fixture_source='Microsoft Graph GET /me (id field per allauth MicrosoftGraphProvider.extract_uid)',
    ),
    'reddit': SupportedProviderFixture(
        slug='reddit',
        expected_uid='reddit_fixture_user',
        profile_document={
            'name': 'reddit_fixture_user',
            'sub': 'decoy-sub-must-not-be-used',
            'id': 'decoy-id',
        },
        fixture_source='Reddit GET /api/v1/me (name per allauth RedditProvider.extract_uid)',
    ),
    'shopify': SupportedProviderFixture(
        slug='shopify',
        expected_uid='654321',
        profile_document={
            'shop': {
                'id': 654321,
                'email': 'owner@fixture-shop.myshopify.com',
                'name': 'Fixture Shop',
                'myshopify_domain': 'fixture-shop.myshopify.com',
            }
        },
        fixture_source='Shopify shop.json (shop.id per allauth ShopifyProvider.extract_uid)',
    ),
    'linkedin': SupportedProviderFixture(
        slug='linkedin',
        expected_uid='linkedin-sub-fixture-001',
        profile_document={
            'sub': 'linkedin-sub-fixture-001',
            'email': 'user-linkedin@example.com',
            'email_verified': True,
            'name': 'LinkedIn Fixture User',
            'id': 'decoy-linkedin-id',
        },
        fixture_source='LinkedIn OIDC discovery (www.linkedin.com + api.linkedin.com); sub claim',
    ),
    'slack': SupportedProviderFixture(
        slug='slack',
        expected_uid='T-SLACK-FIX-001_U-SLACK-FIX-001',
        profile_document={
            'ok': True,
            'sub': 'decoy-sub-not-used-for-uid',
            'https://slack.com/user_id': 'U-SLACK-FIX-001',
            'https://slack.com/team_id': 'T-SLACK-FIX-001',
            'email': 'user-slack@example.com',
            'email_verified': True,
            'name': 'Slack Fixture User',
            'team': {'id': 'decoy-team-id'},
            'user': {'id': 'decoy-user-id'},
        },
        fixture_source='Slack openid.connect.userInfo (https://slack.com/team_id and user_id claims)',
    ),
    'keycloak': SupportedProviderFixture(
        slug='keycloak',
        expected_uid='keycloak-sub-fixture-001',
        profile_document={
            'sub': 'keycloak-sub-fixture-001',
            'email': 'user-keycloak@example.com',
            'email_verified': True,
            'preferred_username': 'keycloak-fixture',
            'id': 'decoy-keycloak-id',
        },
        fixture_source='Keycloak OIDC userinfo (sub); allauth openid_connect provider_id keycloak',
        company_settings_host='keycloak',
    ),
    'openid_connect': SupportedProviderFixture(
        slug='openid_connect',
        expected_uid='generic-oidc-sub-001',
        profile_document={
            'sub': 'generic-oidc-sub-001',
            'email': 'user-oidc@example.com',
            'email_verified': True,
            'name': 'Generic OIDC Fixture User',
            'id': 'decoy-generic-id',
        },
        fixture_source='Generic OIDC userinfo (sub); Keycloak-shaped discovery in strict tests',
        company_settings_host='oidc',
    ),
    'okta': SupportedProviderFixture(
        slug='okta',
        expected_uid='okta-sub-fixture-001',
        profile_document={
            'sub': 'okta-sub-fixture-001',
            'email': 'user-okta@example.com',
            'email_verified': True,
            'given_name': 'Okta',
            'family_name': 'Fixture',
            'id': 'decoy-okta-id',
        },
        fixture_source='Okta GET /oauth2/v1/userinfo (sub per allauth OktaProvider.extract_uid)',
        company_settings_host='okta',
    ),
    'auth0': SupportedProviderFixture(
        slug='auth0',
        expected_uid='auth0-sub-fixture-001',
        profile_document={
            'sub': 'auth0-sub-fixture-001',
            'email': 'user-auth0@example.com',
            'email_verified': True,
            'name': 'Auth0 Fixture User',
            'user_id': 'decoy-auth0-user-id',
        },
        fixture_source='Auth0 GET /userinfo (sub per allauth Auth0Provider.extract_uid)',
        company_settings_host='auth0',
    ),
}
