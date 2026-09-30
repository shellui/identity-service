"""SAML admin save path: slug lookup, client id uniqueness, metadata import."""

from __future__ import annotations

from unittest.mock import patch

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.authapi.tests.oauth_ssrf_test_utils import pin_oauth_http_to_localhost
from apps.authapi.tests.oauth_test_crypto import OAuthMockHttpsServer
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.models import Company, CompanyOAuthClient

User = get_user_model()

METADATA_XML = """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.meta.test/entity">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>ENCRYPTCERTDATA</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>SIGNINGCERTDATA</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.meta.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>
"""


@override_settings(
    SECRET_KEY='test-secret-saml-admin',
    DEBUG=True,
    ALLOWED_HOSTS=['identity.test.example', 'testserver', 'localhost', '127.0.0.1'],
)
class SAMLAdminConfigTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.site = Site.objects.get_current()
        self.company = Company.objects.create(name='Admin Co', slug='admin-co')
        self.owner = User.objects.create_user(username='admin-owner', email='admin@example.com', password='x')
        self.company.members.add(self.owner)
        self.company.owners.add(self.owner)
        tokens = _issue_shellui_tokens(self.owner, company=self.company)
        self.auth = f'Bearer {tokens["access_token"]}'

    def test_duplicate_slug_lookup_returns_not_found(self):
        for name in ('one', 'two'):
            SocialApp.objects.create(
                provider='saml',
                name=name,
                client_id='c1-dupslug0001',
                secret='-',
                settings={'catalog_slug': 'saml', 'shellui_company_id': self.company.id, 'idp': {}},
            )
        response = self.client.get(
            reverse('shellui-saml-metadata', kwargs={'organization_slug': 'c1-dupslug0001'}),
            HTTP_HOST='identity.test.example',
        )
        self.assertEqual(response.status_code, 404)

    def test_put_rejects_client_id_taken_by_another_app(self):
        first = SocialApp.objects.create(
            provider='saml',
            name='first',
            client_id='c1-firstslug0001',
            secret='-',
            settings={
                'catalog_slug': 'saml',
                'shellui_company_id': self.company.id,
                'idp': {
                    'entity_id': 'https://idp.admin.test/one',
                    'sso_url': 'https://idp.admin.test/sso',
                    'x509cert': 'CERTONE',
                },
            },
        )
        SocialApp.objects.create(
            provider='saml',
            name='second',
            client_id='c1-secondslug001',
            secret='-',
            settings={'catalog_slug': 'saml', 'idp': {'entity_id': 'https://idp.admin.test/two'}},
        )
        CompanyOAuthClient.objects.create(company=self.company, social_app=first, is_active=True)
        response = self.client.put(
            f'/api/v1/oauth-social-apps/{first.pk}',
            data={'client_id': 'c1-secondslug001'},
            format='json',
            HTTP_AUTHORIZATION=self.auth,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get('error_code'), 'oauth_app_client_id_taken')
        first.refresh_from_db()
        self.assertEqual(first.client_id, 'c1-firstslug0001')

    def test_metadata_url_only_import_keeps_signing_certificate(self):
        hostname = 'idp.meta.test'

        def _handler(http) -> None:
            body = METADATA_XML.encode('utf-8')
            http.send_response(200)
            http.send_header('Content-Type', 'application/xml')
            http.send_header('Content-Length', str(len(body)))
            http.end_headers()
            http.wfile.write(body)

        server = OAuthMockHttpsServer.start(
            hostnames=[hostname],
            routes={(hostname, 'GET', '/metadata'): _handler},
        )
        try:
            with pin_oauth_http_to_localhost((hostname, server.port)):
                with patch(
                    'apps.actions.webhook_transport.ssl.create_default_context',
                    return_value=server.ssl_client_context(),
                ):
                    response = self.client.post(
                        '/api/v1/oauth-social-apps',
                        data={
                            'docs_slug': 'saml',
                            'extra_settings': {
                                'idp_entity_id': 'https://idp.meta.test/entity',
                                'metadata_url': f'https://{hostname}:{server.port}/metadata',
                            },
                        },
                        format='json',
                        HTTP_AUTHORIZATION=self.auth,
                    )
        finally:
            server.shutdown()
        self.assertEqual(response.status_code, 201, response.data)
        idp = response.data['social_app']['saml']
        self.assertEqual(idp['idp_entity_id'], 'https://idp.meta.test/entity')
        stored = SocialApp.objects.get(client_id__startswith=f'c{self.company.id}-')
        self.assertEqual(stored.settings['idp']['x509cert'], 'SIGNINGCERTDATA')
        self.assertEqual(stored.settings['idp']['sso_url'], 'https://idp.meta.test/sso')
        self.assertNotIn('ENCRYPTCERTDATA', stored.settings['idp']['x509cert'])
