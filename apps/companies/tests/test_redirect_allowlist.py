from django.test import RequestFactory, TestCase

from apps.companies.models import Company, CompanyOAuthRedirect
from apps.companies.redirect_allowlist import (
    normalize_allowlist_origin,
    redirect_url_allowed_for_company,
    validate_redirect_to_for_company,
)


class RedirectAllowlistTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Allowlist Co', slug='allowlist-co')
        self.request = RequestFactory().get('/')

    def test_normalize_allowlist_origin_strips_path(self):
        origin, err = normalize_allowlist_origin('https://App.Example.com/login/callback?x=1')
        self.assertIsNone(err)
        self.assertEqual(origin, 'https://app.example.com')

    def test_loopback_always_allowed_without_rows(self):
        self.assertTrue(
            redirect_url_allowed_for_company(
                self.company,
                'http://127.0.0.1:9876/callback',
                self.request,
            )
        )
        self.assertTrue(
            redirect_url_allowed_for_company(
                self.company,
                'http://localhost:4000/login/callback',
                self.request,
            )
        )

    def test_empty_allowlist_denies_non_loopback(self):
        self.assertFalse(
            redirect_url_allowed_for_company(
                self.company,
                'https://app.example.com/login/callback',
                self.request,
            )
        )

    def test_origin_match_allows_callback_path(self):
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://app.example.com',
            is_active=True,
        )
        self.assertTrue(
            redirect_url_allowed_for_company(
                self.company,
                'https://app.example.com/login/callback',
                self.request,
            )
        )
        self.assertFalse(
            redirect_url_allowed_for_company(
                self.company,
                'https://other.example.com/login/callback',
                self.request,
            )
        )

    def test_inactive_row_ignored(self):
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://app.example.com',
            is_active=False,
        )
        self.assertFalse(
            redirect_url_allowed_for_company(
                self.company,
                'https://app.example.com/login/callback',
                self.request,
            )
        )

    def test_validate_redirect_to_requires_value(self):
        url, err = validate_redirect_to_for_company(
            company=self.company,
            request=self.request,
            redirect_to_raw=None,
        )
        self.assertIsNone(url)
        self.assertIn('Missing redirect_to', err or '')
