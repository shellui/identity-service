from django.test import RequestFactory, TestCase, override_settings

from apps.companies.admin import CompanyOAuthRedirectAdminForm
from apps.companies.models import Company, CompanyOAuthRedirect
from apps.companies.redirect_allowlist import (
    is_custom_scheme_redirect,
    loopback_oauth_redirects_allowed,
    normalize_allowlist_origin,
    normalize_client_redirect_url,
    normalize_desktop_redirect_uri,
    redirect_url_allowed_for_company,
    validate_redirect_to_for_company,
    validate_redirect_uri_for_company,
)


class RedirectAllowlistTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Allowlist Co', slug='allowlist-co')
        self.request = RequestFactory().get('/')

    def test_normalize_allowlist_origin_strips_path(self):
        origin, err = normalize_allowlist_origin('https://App.Example.com/login/callback?x=1')
        self.assertIsNone(err)
        self.assertEqual(origin, 'https://app.example.com')

    @override_settings(OAUTH_ALLOW_LOOPBACK_REDIRECTS=True)
    def test_loopback_allowed_when_explicitly_enabled(self):
        self.assertTrue(loopback_oauth_redirects_allowed())
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

    @override_settings(OAUTH_ALLOW_LOOPBACK_REDIRECTS=False, DEBUG=False)
    def test_loopback_denied_in_production_without_env(self):
        self.assertFalse(loopback_oauth_redirects_allowed())
        self.assertFalse(
            redirect_url_allowed_for_company(
                self.company,
                'http://127.0.0.1:9876/callback',
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

    def test_validate_redirect_uri_requires_value(self):
        url, err = validate_redirect_uri_for_company(
            company=self.company,
            request=self.request,
            redirect_uri_raw=None,
        )
        self.assertIsNone(url)
        self.assertIn('Missing redirect_uri', err or '')

    def test_validate_redirect_uri_denies_non_allowlisted(self):
        url, err = validate_redirect_uri_for_company(
            company=self.company,
            request=self.request,
            redirect_uri_raw='https://evil.example.com/login/callback',
        )
        self.assertIsNone(url)
        self.assertIn('not allowed', err or '')

    def test_https_redirect_still_requires_http_or_https_wording(self):
        url, err = normalize_client_redirect_url(self.request, 'javascript:alert(1)')
        self.assertIsNone(url)
        self.assertEqual(err, 'redirect_to must use http or https.')
        url, err = normalize_client_redirect_url(self.request, 'https://app.example.com/login/callback')
        self.assertEqual(url, 'https://app.example.com/login/callback')
        self.assertIsNone(err)

    def test_desktop_uri_normalizes_exact_scheme_and_host(self):
        uri, err = normalize_desktop_redirect_uri('Shellui-Playground://Callback')
        self.assertIsNone(err)
        self.assertEqual(uri, 'shellui-playground://callback')
        self.assertTrue(is_custom_scheme_redirect(uri))
        dotted, err = normalize_desktop_redirect_uri('Com.Shellui.App://auth')
        self.assertIsNone(err)
        self.assertEqual(dotted, 'com.shellui.app://auth')

    def test_desktop_uri_rejects_dangerous_schemes_userinfo_and_fragment(self):
        for raw in (
            'javascript:alert(1)',
            'file:///tmp/x',
            'data:text/html,hi',
            'vbscript:msgbox(1)',
            'about:blank',
            'blob:https://app.example.com/id',
            'ftp://files.example.com/x',
            'http://app.example.com/callback',
            'https://app.example.com/callback',
            'ms-appx:///index.html',
        ):
            uri, err = normalize_desktop_redirect_uri(raw)
            self.assertIsNone(uri, raw)
            self.assertTrue(err, raw)
        uri, err = normalize_desktop_redirect_uri('shellui-playground://user:pw@callback')
        self.assertIsNone(uri)
        self.assertIn('userinfo', err or '')
        uri, err = normalize_desktop_redirect_uri('shellui-playground://callback#token')
        self.assertIsNone(uri)
        self.assertIn('fragment', err or '')
        url, err = normalize_client_redirect_url(self.request, 'shellui-playground://callback#token')
        self.assertIsNone(url)
        self.assertEqual(err, 'redirect_to must not include a fragment.')

    def test_desktop_allowlist_is_exact_and_ignores_web_rows(self):
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            kind=CompanyOAuthRedirect.KIND_DESKTOP,
            base_url='shellui-playground://callback',
            is_active=True,
        )
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            kind=CompanyOAuthRedirect.KIND_WEB,
            base_url='https://app.example.com',
            is_active=True,
        )
        self.assertTrue(
            redirect_url_allowed_for_company(
                self.company,
                'shellui-playground://callback',
                self.request,
            )
        )
        self.assertFalse(
            redirect_url_allowed_for_company(
                self.company,
                'shellui-playground://callback/extra',
                self.request,
            )
        )
        self.assertFalse(
            redirect_url_allowed_for_company(
                self.company,
                'shellui-playground://other',
                self.request,
            )
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
                'https://shellui-playground/callback',
                self.request,
            )
        )

    def test_inactive_desktop_row_is_ignored(self):
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            kind=CompanyOAuthRedirect.KIND_DESKTOP,
            base_url='shellui-playground://callback',
            is_active=False,
        )
        self.assertFalse(
            redirect_url_allowed_for_company(
                self.company,
                'shellui-playground://callback',
                self.request,
            )
        )

    def test_admin_form_normalizes_desktop_and_rejects_javascript(self):
        form = CompanyOAuthRedirectAdminForm(
            data={
                'company': self.company.id,
                'kind': CompanyOAuthRedirect.KIND_DESKTOP,
                'base_url': 'Shellui-Playground://Callback',
                'label': 'Playground',
                'source': CompanyOAuthRedirect.SOURCE_MANUAL,
                'is_active': True,
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data['base_url'], 'shellui-playground://callback')
        rejected = CompanyOAuthRedirectAdminForm(
            data={
                'company': self.company.id,
                'kind': CompanyOAuthRedirect.KIND_DESKTOP,
                'base_url': 'javascript:alert(1)',
                'label': '',
                'source': CompanyOAuthRedirect.SOURCE_MANUAL,
                'is_active': True,
            }
        )
        self.assertFalse(rejected.is_valid())
        self.assertIn('base_url', rejected.errors)
