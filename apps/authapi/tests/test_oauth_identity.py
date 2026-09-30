from unittest.mock import patch

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.test import TestCase

from allauth.socialaccount.models import SocialApp

from apps.authapi.oauth_allauth import sociallogin_userinfo
from apps.authapi.oauth_user import (
    OAuthProfile,
    extract_oauth_profile,
    get_or_create_user_for_oauth,
    microsoft_email_trustworthy,
    resolve_oauth_user,
)
from apps.authapi.provider_registry import get_provider_catalog
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
            social_provider='google',
            social_uid='attacker-sub',
            email='victim@example.com',
            full_name='Attacker',
            avatar_url=None,
            email_verified_for_link=False,
            userinfo={'sub': 'attacker-sub', 'email_verified': False},
        )
        user, created, err = resolve_oauth_user(provider='google', profile=profile)
        self.assertIsNone(err)
        self.assertTrue(created)
        self.assertNotEqual(user.pk, self.victim.pk)
        self.assertTrue(user.email.endswith('@google.local'))

    def test_google_verified_email_links_existing_user(self):
        profile = OAuthProfile(
            provider_id='victim-sub',
            social_provider='google',
            social_uid='victim-sub',
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
            social_provider='google',
            social_uid='attacker-sub',
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

    def test_duplicate_email_rows_use_lowest_pk(self):
        first = User.objects.create_user(username='u1', email='dup@example.com', password='x')
        User.objects.create_user(username='u2', email='DUP@example.com', password='x')
        profile = OAuthProfile(
            provider_id='sub-dup',
            social_provider='google',
            social_uid='sub-dup',
            email='dup@example.com',
            full_name='Dup User',
            avatar_url=None,
            email_verified_for_link=True,
            userinfo={'email_verified': True},
        )
        user, created, err = resolve_oauth_user(provider='google', profile=profile)
        self.assertIsNone(err)
        self.assertFalse(created)
        self.assertEqual(user.pk, first.pk)

    def test_get_or_create_user_for_oauth_helper(self):
        user, created = get_or_create_user_for_oauth(
            email='new@example.com',
            defaults={'username': 'oauth_new'},
        )
        self.assertTrue(created)
        self.assertEqual(user.email, 'new@example.com')

    def test_microsoft_dedicated_tenant_allows_profile(self):
        tenant_id = '11111111-1111-1111-1111-111111111111'
        profile, err = extract_oauth_profile(
            'microsoft',
            {'id': 'ms-2', 'mail': 'user@contoso.com'},
            'token',
            tenant=tenant_id,
            id_token_claims={'tid': tenant_id},
        )
        self.assertIsNone(err)
        assert profile is not None
        self.assertTrue(profile.email_verified_for_link)

    def test_battlenet_extract_oauth_profile_uses_allauth_uid_for_china(self):
        entry = get_provider_catalog().by_slug()['battlenet']
        app = SocialApp(provider='battlenet', client_id='bn', secret='s')
        userinfo = {'id': 7, 'region': 'cn', 'battletag': 'Cn#7'}
        profile, err = extract_oauth_profile(
            'battlenet',
            userinfo,
            'token',
            catalog_entry=entry,
            social_app=app,
        )
        self.assertIsNone(err)
        assert profile is not None
        self.assertEqual(profile.social_uid, '7-cn')
        self.assertEqual(profile.provider_id, '7-cn')

    def test_sociallogin_userinfo_propagates_allauth_account_uid(self):
        from types import SimpleNamespace

        account = SimpleNamespace(
            uid='7-cn',
            extra_data={'id': 7, 'region': 'cn', 'battletag': 'Cn#7'},
        )
        user = SimpleNamespace(email='', get_full_name=lambda: '')
        sociallogin = SimpleNamespace(account=account, user=user, state={})
        data = sociallogin_userinfo(sociallogin)
        self.assertEqual(data['_allauth_account_uid'], '7-cn')
        self.assertEqual(data['id'], 7)
