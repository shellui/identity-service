"""Hand-written OAuth profile documents for the eight supported providers in this release.

Expected uids are literal constants (never derived from extract_uid in tests).
Profile shapes follow each provider's API / allauth adapter field names.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# This release: identity-hosted OAuth for these providers only.
RELEASE_SUPPORTED_OAUTH_SLUGS: frozenset[str] = frozenset(
    {
        'apple',
        'github',
        'gitlab',
        'google',
        'line',
        'microsoft',
        'reddit',
        'shopify',
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
        return {'gitlab_url': company_gitlab_url(company_slug)}
    if slug == 'microsoft':
        return {'tenant': '11111111-1111-1111-1111-111111111111'}
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
}
