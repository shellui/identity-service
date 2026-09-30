"""SAML SP-initiated login entrypoint security."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.authapi.saml.request_id import SAML_REQUEST_ID_PREFIX
from apps.authapi.saml.views import SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY
from apps.authapi.tests.saml_test_crypto import generate_test_idp_credentials
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect


@override_settings(
    SECRET_KEY='test-secret-saml-login',
    DEBUG=True,
    OAUTH_TOKEN_DELIVERY='code',
    ALLOWED_HOSTS=['identity.test.example', 'testserver', 'localhost', '127.0.0.1'],
)
class SAMLLoginSecurityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.site = Site.objects.get_current()
        self.company = Company.objects.create(name='Login Co', slug='login-co')
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )
        self.creds = generate_test_idp_credentials(entity_id='https://idp.test.example/login-co')
        self.app = SocialApp.objects.create(
            provider='saml',
            name='login-test',
            client_id='c1-logintestslug',
            secret='-',
            settings={
                'catalog_slug': 'saml',
                'shellui_company_id': self.company.id,
                'idp': {
                    'entity_id': self.creds.entity_id,
                    'sso_url': 'https://idp.test.example/sso',
                    'x509cert': self.creds.x509cert_one_line,
                },
                'advanced': {'reject_idp_initiated_sso': True},
            },
        )
        self.app.sites.add(self.site)
        CompanyOAuthClient.objects.create(company=self.company, social_app=self.app, is_active=True)
        self.http_host = 'identity.test.example'

    def test_login_rejects_open_redirect(self):
        login_url = reverse('shellui-saml-login', kwargs={'organization_slug': self.app.client_id})
        response = self.client.get(
            login_url,
            data={
                'redirect_to': 'https://evil.example/phish',
                'company_id': str(self.company.id),
            },
            follow=False,
            HTTP_HOST=self.http_host,
        )
        self.assertEqual(response.status_code, 400)
        body = response.json()
        self.assertEqual(body['error_code'], 'redirect_not_allowed')

    def _login(self, **params):
        login_url = reverse('shellui-saml-login', kwargs={'organization_slug': self.app.client_id})
        return self.client.get(
            login_url,
            data={
                'redirect_to': 'https://shell.example.com/callback',
                **params,
            },
            follow=False,
            HTTP_HOST=self.http_host,
        )

    def _stashed_token_delivery(self) -> str:
        import hashlib

        from django.core.cache import cache

        request_id = self.client.session[SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY]
        digest = hashlib.sha256(str(request_id).encode('utf-8')).hexdigest()
        payload = cache.get(f'{SAML_REQUEST_ID_PREFIX}{digest}')
        return str(payload.get('token_delivery'))

    def test_login_stores_fragment_token_delivery_like_authorize(self):
        response = self._login(token_delivery='fragment')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._stashed_token_delivery(), 'fragment')

    def test_login_ignores_unknown_token_delivery(self):
        response = self._login(token_delivery='cookie')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._stashed_token_delivery(), 'code')
