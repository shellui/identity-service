"""SAML SP-initiated login entrypoint security."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect


@override_settings(
    SECRET_KEY='test-secret-saml-login',
    DEBUG=True,
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
        self.app = SocialApp.objects.create(
            provider='saml',
            name='login-test',
            client_id='c1-logintestslug',
            secret='-',
            settings={
                'catalog_slug': 'saml',
                'shellui_company_id': self.company.id,
                'idp': {
                    'entity_id': 'https://idp.test.example/login-co',
                    'sso_url': 'https://idp.test.example/sso',
                    'x509cert': 'MIICplaceholder',
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
