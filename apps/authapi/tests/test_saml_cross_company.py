"""Cross-company SAML isolation (entity id reuse must not link accounts)."""

from __future__ import annotations

import json

from allauth.socialaccount.models import SocialAccount, SocialApp
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.authapi.oauth_social_account import saml_social_account_provider_key
from apps.authapi.saml.request_id import stash_saml_request_id
from apps.authapi.saml.utils import sp_public_urls
from apps.authapi.saml.views import SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY
from apps.authapi.tests.saml_test_crypto import build_signed_saml_response, generate_test_idp_credentials
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect

User = get_user_model()


@override_settings(
    SECRET_KEY='test-secret-saml-cross',
    DEBUG=True,
    ALLOWED_HOSTS=['identity.test.example', 'testserver', 'localhost', '127.0.0.1'],
)
class SAMLCrossCompanyIsolationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.site = Site.objects.get_current()
        self.company_a = Company.objects.create(name='Co A', slug='co-a')
        self.company_b = Company.objects.create(name='Co B', slug='co-b')
        for company in (self.company_a, self.company_b):
            CompanyOAuthRedirect.objects.create(
                company=company,
                base_url='https://shell.example.com',
                is_active=True,
            )
        self.shared_entity_id = 'https://idp.test.example/shared-entity'
        self.creds_a = generate_test_idp_credentials(entity_id=self.shared_entity_id)
        self.creds_b = generate_test_idp_credentials(entity_id=self.shared_entity_id)
        self.app_a = SocialApp.objects.create(
            provider='saml',
            name='a-idp',
            client_id='c1-company-a-slug1',
            secret='-',
            settings={
                'catalog_slug': 'saml',
                'shellui_company_id': self.company_a.id,
                'idp': {
                    'entity_id': self.shared_entity_id,
                    'sso_url': 'https://idp-a.test.example/sso',
                    'x509cert': self.creds_a.x509cert_one_line,
                },
                'advanced': {'reject_idp_initiated_sso': True},
            },
        )
        self.app_b = SocialApp.objects.create(
            provider='saml',
            name='b-idp',
            client_id='c2-company-b-slug1',
            secret='-',
            settings={
                'catalog_slug': 'saml',
                'shellui_company_id': self.company_b.id,
                'idp': {
                    'entity_id': self.shared_entity_id,
                    'sso_url': 'https://idp-b.test.example/sso',
                    'x509cert': self.creds_b.x509cert_one_line,
                },
                'advanced': {'reject_idp_initiated_sso': True},
            },
        )
        self.app_a.sites.add(self.site)
        self.app_b.sites.add(self.site)
        CompanyOAuthClient.objects.create(company=self.company_a, social_app=self.app_a, is_active=True)
        CompanyOAuthClient.objects.create(company=self.company_b, social_app=self.app_b, is_active=True)
        self.http_host = 'identity.test.example'
        req = self.client.get('/', HTTP_HOST=self.http_host).wsgi_request
        self.sp_a = sp_public_urls(req, self.app_a.client_id, settings_data=self.app_a.settings)
        self.sp_b = sp_public_urls(req, self.app_b.client_id, settings_data=self.app_b.settings)

    def _finish_acs(self, *, app: SocialApp, sp: dict, creds, name_id: str, request_id: str) -> int:
        stash_saml_request_id(
            request_id=request_id,
            payload={
                'company_id': app.settings['shellui_company_id'],
                'redirect_to': 'https://shell.example.com/callback',
                'token_delivery': 'code',
            },
        )
        saml = build_signed_saml_response(
            creds=creds,
            sp_entity_id=sp['entity_id'],
            acs_url=sp['acs_url'],
            name_id=name_id,
            in_response_to=request_id,
        )
        session = self.client.session
        session[SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY] = request_id
        session.save()
        acs_url = reverse('shellui-saml-acs', kwargs={'organization_slug': app.client_id})
        response = self.client.post(
            acs_url,
            data={'SAMLResponse': saml},
            follow=False,
            HTTP_HOST=self.http_host,
        )
        finish = self.client.get(response['Location'], follow=False, HTTP_HOST=self.http_host)
        return finish.status_code

    def test_company_b_acs_does_not_sign_in_company_a_user(self):
        victim_subject = 'victim-subject-001'
        status_a = self._finish_acs(
            app=self.app_a,
            sp=self.sp_a,
            creds=self.creds_a,
            name_id=victim_subject,
            request_id='_victimlogin001',
        )
        self.assertIn(status_a, {302, 200})
        provider_a = saml_social_account_provider_key(self.app_a)
        self.assertEqual(provider_a, f'saml-{self.app_a.pk}')
        self.assertNotEqual(provider_a, 'saml')
        linked = SocialAccount.objects.filter(provider=provider_a).select_related('user').first()
        self.assertIsNotNone(linked)
        user_a = linked.user

        status_b = self._finish_acs(
            app=self.app_b,
            sp=self.sp_b,
            creds=self.creds_b,
            name_id=victim_subject,
            request_id='_attackerlogin01',
        )
        self.assertIn(status_b, {302, 200})
        provider_b = saml_social_account_provider_key(self.app_b)
        account_b = SocialAccount.objects.filter(provider=provider_b).select_related('user').first()
        self.assertIsNotNone(account_b)
        self.assertNotEqual(account_b.user_id, user_a.id)
        self.assertFalse(SocialAccount.objects.filter(provider='saml', user=user_a).exists())

    def test_social_app_cannot_be_mapped_to_a_second_company(self):
        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            CompanyOAuthClient.objects.create(company=self.company_b, social_app=self.app_a, is_active=True)
