"""SAML IdP entity ID must be globally unique per company."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.views import _issue_shellui_tokens
from apps.companies.models import Company

User = get_user_model()


@override_settings(
    SECRET_KEY='test-secret-saml-entity',
    DEBUG=True,
)
class SAMLEntityIdUniquenessTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.site = Site.objects.get_current()
        self.company_a = Company.objects.create(name='Entity A', slug='entity-a')
        self.company_b = Company.objects.create(name='Entity B', slug='entity-b')
        self.owner_b = User.objects.create_user(username='owner-b', email='b@example.com', password='x')
        self.company_b.members.add(self.owner_b)
        self.company_b.owners.add(self.owner_b)
        tokens = _issue_shellui_tokens(self.owner_b, company=self.company_b)
        self.auth = f'Bearer {tokens["access_token"]}'
        SocialApp.objects.create(
            provider='saml',
            name='first',
            client_id='c1-firstentity01',
            secret='-',
            settings={
                'catalog_slug': 'saml',
                'shellui_company_id': self.company_a.id,
                'idp': {
                    'entity_id': 'https://idp.example.com/shared',
                    'sso_url': 'https://idp.example.com/sso',
                    'x509cert': 'MIIBdummy',
                },
            },
        )

    def test_api_rejects_duplicate_entity_id_for_another_company(self):
        response = self.client.post(
            '/api/v1/oauth-social-apps',
            data={
                'docs_slug': 'saml',
                'extra_settings': {
                    'idp_entity_id': 'https://idp.example.com/shared',
                    'sso_url': 'https://example.com/saml-sso-alt',
                    'x509cert': 'MIIBotherdummy',
                },
            },
            format='json',
            HTTP_AUTHORIZATION=self.auth,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get('error_code'), 'saml_idp_entity_id_in_use')
