from unittest.mock import patch

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.authapi.oauth_user import (
    OAuthProfile,
    extract_oauth_profile,
    microsoft_email_trustworthy,
    resolve_oauth_user,
)
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()


class OAuthIdentityResolutionTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='OAuth Id', slug='oauth-id')
        self.victim = User.objects.create_user(
            username='victim',
            email='victim@example.com',
            password='unused',
        )
        set_company_access(self.company, self.victim, enabled=True)

    def test_google_unverified_email_does_not_link_existing_user(self):
        profile = OAuthProfile(
            provider_id='attacker-sub',
            email='victim@example.com',
            full_name='Attacker',
            avatar_url=None,
            email_verified_for_link=False,
            userinfo={'sub': 'attacker-sub', 'email_verified': False},
        )
        user, created, err = resolve_oauth_user(provider='google', profile=profile)
        self.assertIsNone(user)
        self.assertFalse(created)
        self.assertIn('verify', (err or '').lower())

    def test_google_verified_email_links_existing_user(self):
        profile = OAuthProfile(
            provider_id='victim-sub',
            email='victim@example.com',
            full_name='Victim',
            avatar_url=None,
            email_verified_for_link=True,
            userinfo={'sub': 'victim-sub', 'email_verified': True},
        )
        user, created, err = resolve_oauth_user(provider='google', profile=profile)
        self.assertIsNone(err)
        self.assertFalse(created)
        self.assertEqual(user.pk, self.victim.pk)

    def test_provider_uid_wins_over_unverified_email(self):
        attacker = User.objects.create_user(
            username='attacker',
            email='attacker@example.com',
            password='unused',
        )
        SocialAccount.objects.create(
            provider='google',
            uid='attacker-sub',
            user=attacker,
            extra_data={},
        )
        profile = OAuthProfile(
            provider_id='attacker-sub',
            email='victim@example.com',
            full_name='Attacker',
            avatar_url=None,
            email_verified_for_link=False,
            userinfo={'sub': 'attacker-sub'},
        )
        user, _created, err = resolve_oauth_user(provider='google', profile=profile)
        self.assertIsNone(err)
        self.assertEqual(user.pk, attacker.pk)

    @patch(
        'apps.authapi.oauth_user._fetch_github_verified_primary_email',
        return_value=(None, False),
    )
    def test_github_requires_verified_primary_email(self, _fetch):
        profile, err = extract_oauth_profile(
            'github',
            {'id': 99, 'login': 'ghost'},
            'token',
        )
        self.assertIsNone(profile)
        self.assertIn('verified', (err or '').lower())

    def test_microsoft_common_tenant_requires_xms_edov(self):
        self.assertFalse(
            microsoft_email_trustworthy(tenant='common', id_token_claims={'xms_edov': False})
        )
        profile, err = extract_oauth_profile(
            'microsoft',
            {'id': 'ms-1', 'mail': 'victim@example.com'},
            'token',
            tenant='common',
            id_token_claims={'xms_edov': False},
        )
        self.assertIsNone(profile)
        self.assertIn('Microsoft', err or '')

    def test_microsoft_dedicated_tenant_allows_profile(self):
        profile, err = extract_oauth_profile(
            'microsoft',
            {'id': 'ms-2', 'mail': 'user@contoso.com'},
            'token',
            tenant='contoso.onmicrosoft.com',
            id_token_claims={},
        )
        self.assertIsNone(err)
        assert profile is not None
        self.assertTrue(profile.email_verified_for_link)
