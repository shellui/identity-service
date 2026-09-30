"""Admin advanced settings cannot weaken SAML signature requirements."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.authapi.saml.request_id import stash_saml_request_id
from apps.authapi.saml.utils import merge_shellui_advanced, sp_public_urls
from apps.authapi.saml.views import SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY
from apps.authapi.tests.saml_test_crypto import build_signed_saml_response, generate_test_idp_credentials
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect


@override_settings(
    SECRET_KEY='test-secret-saml-strict',
    DEBUG=True,
    ALLOWED_HOSTS=['identity.test.example', 'testserver', 'localhost', '127.0.0.1'],
)
class SAMLStrictAdvancedTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.site = Site.objects.get_current()
        self.company = Company.objects.create(name='Strict Co', slug='strict-co')
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )
        self.creds = generate_test_idp_credentials()
        self.app = SocialApp.objects.create(
            provider='saml',
            name='strict-test',
            client_id='c1-strictslug001',
            secret='-',
            settings={
                'catalog_slug': 'saml',
                'shellui_company_id': self.company.id,
                'idp': {
                    'entity_id': self.creds.entity_id,
                    'sso_url': 'https://idp.test.example/sso',
                    'x509cert': self.creds.x509cert_one_line,
                },
                'advanced': {
                    'strict': False,
                    'want_assertion_signed': False,
                    'want_message_signed': False,
                },
            },
        )
        self.app.sites.add(self.site)
        CompanyOAuthClient.objects.create(company=self.company, social_app=self.app, is_active=True)
        req = self.client.get('/', HTTP_HOST='identity.test.example').wsgi_request
        self.sp = sp_public_urls(req, self.app.client_id, settings_data=self.app.settings)
        self.http_host = 'identity.test.example'

    def test_merge_shellui_advanced_ignores_weakening_overrides(self):
        merged = merge_shellui_advanced(self.app.settings['advanced'])
        self.assertTrue(merged['strict'])
        self.assertTrue(merged['want_assertion_signed'])
        self.assertFalse(merged['want_message_signed'])

    def test_unsigned_assertion_rejected_even_when_advanced_requests_weak_mode(self):
        request_id = '_strictunsigned1'
        stash_saml_request_id(
            request_id=request_id,
            payload={
                'company_id': self.company.id,
                'redirect_to': 'https://shell.example.com/callback',
                'token_delivery': 'code',
            },
        )
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='unsigned-user',
            in_response_to=request_id,
        )
        import base64
        from lxml import etree

        xml = base64.b64decode(saml.encode('ascii'))
        root = etree.fromstring(xml)
        for el in root.xpath('//*[local-name()="Signature"]'):
            el.getparent().remove(el)
        tampered = base64.b64encode(etree.tostring(root)).decode('ascii')
        session = self.client.session
        session[SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY] = request_id
        session.save()
        acs_url = reverse('shellui-saml-acs', kwargs={'organization_slug': self.app.client_id})
        response = self.client.post(
            acs_url,
            data={'SAMLResponse': tampered},
            follow=False,
            HTTP_HOST=self.http_host,
        )
        finish = self.client.get(response['Location'], follow=False, HTTP_HOST=self.http_host)
        self.assertEqual(finish.status_code, 400)
