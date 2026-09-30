"""SAML ACS security tests with real signed responses (no stubbed verification)."""

from __future__ import annotations

import datetime
import json

from allauth.socialaccount.models import SocialAccount, SocialApp
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.authapi.oauth_social_account import saml_social_account_provider_key
from apps.authapi.saml.request_id import stash_saml_request_id
from apps.authapi.saml.views import SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY
from apps.authapi.saml.utils import sp_public_urls
from apps.authapi.tests.saml_test_crypto import build_signed_saml_response, generate_test_idp_credentials
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect

User = get_user_model()


@override_settings(
    SECRET_KEY='test-secret-saml',
    DEBUG=True,
    ALLOWED_HOSTS=['identity.test.example', 'testserver', 'localhost', '127.0.0.1'],
)
class SAMLACSSecurityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.site = Site.objects.get_current()
        self.company = Company.objects.create(name='SAML Co', slug='saml-co', allowed_email_domains=['example.com'])
        self.company_b = Company.objects.create(name='Other Co', slug='other-co')
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )
        self.creds = generate_test_idp_credentials()
        self.app = SocialApp.objects.create(
            provider='saml',
            name='saml-test',
            client_id='c1-testorgslug001',
            secret='-',
            settings={
                'catalog_slug': 'saml',
                'shellui_company_id': self.company.id,
                'idp': {
                    'entity_id': self.creds.entity_id,
                    'sso_url': 'https://idp.test.example/sso',
                    'x509cert': self.creds.x509cert_one_line,
                },
                'attribute_mapping': {
                    'uid': ['urn:oasis:names:tc:SAML:attribute:subject-id'],
                    'email': ['urn:oid:0.9.2342.19200300.100.1.3'],
                },
                'advanced': {'strict': True, 'want_assertion_signed': True, 'reject_idp_initiated_sso': True},
            },
        )
        self.app.sites.add(self.site)
        CompanyOAuthClient.objects.create(company=self.company, social_app=self.app, is_active=True)
        self.mapping = CompanyOAuthClient.objects.get(company=self.company, social_app=self.app)
        request = self.client.get('/', HTTP_HOST='identity.test.example').wsgi_request
        self.sp = sp_public_urls(request, self.app.client_id, settings_data=self.app.settings)
        self.http_host = 'identity.test.example'

    def _post_saml(
        self,
        saml_b64: str,
        *,
        request_id: str | None = None,
        request_payload: dict | None = None,
        return_response: bool = False,
    ):
        if request_id and request_payload is not None:
            stash_saml_request_id(request_id=request_id, payload=request_payload)
        elif request_id:
            stash_saml_request_id(
                request_id=request_id,
                payload={
                    'company_id': self.company.id,
                    'redirect_to': 'https://shell.example.com/callback',
                    'token_delivery': 'code',
                },
            )
        acs_url = reverse('shellui-saml-acs', kwargs={'organization_slug': self.app.client_id})
        finish_url = reverse('shellui-saml-finish-acs', kwargs={'organization_slug': self.app.client_id})
        session = self.client.session
        if request_id:
            session[SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY] = request_id
        session.save()
        response = self.client.post(
            acs_url,
            data={'SAMLResponse': saml_b64},
            follow=False,
            HTTP_HOST=self.http_host,
        )
        if response.status_code in {301, 302, 303} and response['Location'].endswith('/acs/finish/'):
            finish = self.client.get(response['Location'], follow=False)
            if return_response:
                return finish
            return finish.status_code
        if response.status_code in {301, 302, 303}:
            follow = self.client.get(response['Location'], follow=False)
            if return_response:
                return follow
            return follow.status_code
        if return_response:
            return response
        return response.status_code

    def _assert_rejected(self, saml_b64: str, request_id: str | None, error_code: str) -> None:
        finish = self._post_saml(saml_b64, request_id=request_id, return_response=True)
        self.assertEqual(finish.status_code, 400)
        self.assertEqual(finish.content.decode(), error_code)

    def test_valid_login_accepts_signed_assertion(self):
        request_id = '_validrequest001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-001',
            in_response_to=request_id,
        )
        status = self._post_saml(saml, request_id=request_id)
        self.assertIn(status, {302, 200})

    def test_rejects_unsigned_response(self):
        request_id = '_unsignedreq001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-002',
            in_response_to=request_id,
        )
        import base64
        from lxml import etree

        xml = base64.b64decode(saml.encode('ascii'))
        root = etree.fromstring(xml)
        for el in root.xpath('//*[local-name()="Signature"]'):
            el.getparent().remove(el)
        tampered = base64.b64encode(etree.tostring(root)).decode('ascii')
        self._assert_rejected(tampered, request_id, 'saml_signature_missing')

    def test_rejects_wrong_audience(self):
        request_id = '_audiencereq001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id='https://wrong-sp.example/metadata/',
            acs_url=self.sp['acs_url'],
            name_id='user-003',
            in_response_to=request_id,
            audience='https://wrong-sp.example/metadata/',
        )
        self._assert_rejected(saml, request_id, 'saml_audience_mismatch')

    def test_rejects_wrong_issuer(self):
        request_id = '_issuerreq001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-004',
            in_response_to=request_id,
            issuer='https://evil-idp.example/entity',
        )
        self._assert_rejected(saml, request_id, 'saml_issuer_mismatch')

    def test_rejects_expired_assertion(self):
        request_id = '_expiredreq001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-005',
            in_response_to=request_id,
            not_on_or_after_offset_seconds=-120,
        )
        self._assert_rejected(saml, request_id, 'saml_subject_confirmation_invalid')

    def test_rejects_replayed_assertion_id(self):
        assertion_id = '_replay-assertion-id'
        request_id_a = '_replayreq001a'
        saml_a = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-006a',
            in_response_to=request_id_a,
            assertion_id=assertion_id,
        )
        first = self._post_saml(saml_a, request_id=request_id_a)
        self.assertIn(first, {302, 200})
        request_id_b = '_replayreq001b'
        stash_saml_request_id(
            request_id=request_id_b,
            payload={
                'company_id': self.company.id,
                'redirect_to': 'https://shell.example.com/callback',
                'token_delivery': 'code',
            },
        )
        saml_b = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-006b',
            in_response_to=request_id_b,
            assertion_id=assertion_id,
        )
        self._assert_rejected(saml_b, request_id_b, 'saml_assertion_replay')

    def test_rejects_reused_in_response_to(self):
        request_id = '_reuseirtreq01'
        saml_first = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-006c',
            in_response_to=request_id,
            assertion_id='_assert-first-001',
        )
        first = self._post_saml(saml_first, request_id=request_id)
        self.assertIn(first, {302, 200})
        saml_second = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-006d',
            in_response_to=request_id,
            assertion_id='_assert-second-002',
        )
        self._assert_rejected(saml_second, request_id, 'saml_in_response_to_invalid')

    def test_rejects_in_response_to_without_login_session_binding(self):
        request_id = '_crossbrowser01'
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
            name_id='user-006e',
            in_response_to=request_id,
        )
        other_client = Client()
        acs_url = reverse('shellui-saml-acs', kwargs={'organization_slug': self.app.client_id})
        response = other_client.post(
            acs_url,
            data={'SAMLResponse': saml},
            follow=False,
            HTTP_HOST=self.http_host,
        )
        self.assertEqual(response.status_code, 302)
        finish = other_client.get(response['Location'], follow=False, HTTP_HOST=self.http_host)
        self.assertEqual(finish.status_code, 400)
        self.assertEqual(finish.content.decode(), 'saml_in_response_to_session_mismatch')

    def test_rejects_wrong_destination(self):
        request_id = '_destreq001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-dest',
            in_response_to=request_id,
            destination='https://evil.example/acs',
        )
        self._assert_rejected(saml, request_id, 'saml_destination_mismatch')

    def test_rejects_destination_that_only_starts_with_acs_url(self):
        request_id = '_destprefix001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-dest-prefix',
            in_response_to=request_id,
            destination=self.sp['acs_url'] + 'evil/',
        )
        self._assert_rejected(saml, request_id, 'saml_destination_mismatch')

    def test_rejects_recipient_that_only_contains_acs_url(self):
        request_id = '_recipsubstr001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-recip-substr',
            in_response_to=request_id,
            recipient='https://evil.example/?next=' + self.sp['acs_url'],
        )
        self._assert_rejected(saml, request_id, 'saml_recipient_mismatch')

    def test_rejects_envelope_in_response_to_missing_from_signed_assertion(self):
        import base64

        from lxml import etree

        request_id = '_envelopeirt001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-envelope-irt',
            in_response_to=None,
        )
        root = etree.fromstring(base64.b64decode(saml.encode('ascii')))
        root.set('InResponseTo', request_id)
        forged = base64.b64encode(etree.tostring(root)).decode('ascii')
        self._assert_rejected(forged, request_id, 'saml_in_response_to_mismatch')

    def test_rejects_wrong_recipient(self):
        request_id = '_recipreq001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-recip',
            in_response_to=request_id,
            recipient='https://evil.example/acs',
        )
        self._assert_rejected(saml, request_id, 'saml_subject_confirmation_invalid')

    def test_rejects_assertion_valid_beyond_replay_ttl(self):
        request_id = '_longlived001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-long',
            in_response_to=request_id,
            not_on_or_after_offset_seconds=3600,
        )
        self._assert_rejected(saml, request_id, 'saml_assertion_lifetime_invalid')

    def test_rejects_signature_wrapping_attempt(self):
        request_id = '_wrapreq001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='attacker',
            in_response_to=request_id,
            wrap_signature=True,
        )
        self._assert_rejected(saml, request_id, 'saml_assertion_count_invalid')

    def test_rejects_idp_initiated_by_default(self):
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-idp-init',
            in_response_to=None,
        )
        self._assert_rejected(saml, None, 'saml_idp_initiated_rejected')

    def test_company_mismatch_blocked(self):
        other_app = SocialApp.objects.create(
            provider='saml',
            name='other',
            client_id='c2-otherorg00001',
            secret='-',
            settings={
                'catalog_slug': 'saml',
                'shellui_company_id': self.company_b.id,
                'idp': {
                    'entity_id': self.creds.entity_id,
                    'sso_url': 'https://idp.test.example/sso',
                    'x509cert': self.creds.x509cert_one_line,
                },
                'advanced': {'reject_idp_initiated_sso': True},
            },
        )
        CompanyOAuthClient.objects.create(company=self.company_b, social_app=other_app, is_active=True)
        request_id = '_companyreq001'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='user-007',
            in_response_to=request_id,
        )
        status = self._post_saml(
            saml,
            request_id=request_id,
            request_payload={'company_id': self.company_b.id, 'redirect_to': 'https://shell.example.com/cb'},
        )
        self.assertIn(status, {400, 403})

    def test_email_link_only_when_trusted_for_verified_domain(self):
        existing = User.objects.create_user(
            username='linked',
            email='person@example.com',
            password='unused',
        )
        self.company.members.add(existing)
        self.company.verified_email_domains = ['example.com']
        self.company.save(update_fields=['verified_email_domains'])
        self.app.settings['trusted_for_verified_domains'] = True
        self.app.save(update_fields=['settings'])
        request_id = '_emaillinkreq01'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='person@example.com',
            in_response_to=request_id,
        )
        status = self._post_saml(saml, request_id=request_id)
        self.assertIn(status, {302, 200})
        provider_key = saml_social_account_provider_key(self.app)
        account = SocialAccount.objects.filter(user=existing, provider=provider_key).first()
        self.assertIsNotNone(account)

    def test_malicious_idp_asserting_foreign_user_email_returns_conflict(self):
        victim = User.objects.create_user(
            username='victim-user',
            email='victim@victimco.example',
            password='unused',
        )
        self.app.settings['trusted_for_verified_domains'] = True
        self.app.save(update_fields=['settings'])
        self.company.allowed_email_domains = ['victimco.example']
        self.company.verified_email_domains = []
        self.company.save(update_fields=['allowed_email_domains', 'verified_email_domains'])
        request_id = '_maliciousemail01'
        saml = build_signed_saml_response(
            creds=self.creds,
            sp_entity_id=self.sp['entity_id'],
            acs_url=self.sp['acs_url'],
            name_id='attacker-controlled-uid',
            assertion_email='victim@victimco.example',
            in_response_to=request_id,
        )
        finish = self._post_saml(saml, request_id=request_id, return_response=True)
        self.assertEqual(finish.status_code, 400)
        body = json.loads(finish.content.decode())
        self.assertEqual(body['error_code'], 'saml_email_conflict')
        self.assertFalse(SocialAccount.objects.filter(user=victim).exists())
        victim.refresh_from_db()
        self.assertEqual(victim.email, 'victim@victimco.example')
