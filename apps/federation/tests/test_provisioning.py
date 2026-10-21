"""Regional provisioning API as saas-service calls it."""

from __future__ import annotations

import json
import uuid

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.jwks import generate_rsa_key_pair
from apps.companies.models import Company, CompanyOAuthRedirect
from apps.federation.models import CompanyPlan, ProvisionedCompany, UpstreamAccount
from apps.federation.provisioning import b64_sha256
from apps.federation.signing import unix_now

User = get_user_model()

GLOBAL = 'https://id.example'
DASHBOARD = 'https://dashboard.example'
AUDIENCE = 'id.eu.example'
KID = 'dashboard-1'
BASE = '/api/v1/provisioning'


class ProvisioningApiTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.private, cls.public = generate_rsa_key_pair(2048)
        cls.other_private, _ = generate_rsa_key_pair(2048)

    def setUp(self):
        override = override_settings(
            SHELLUI_INSTANCE_ROLE='region',
            JWT_ISSUER='https://id.eu.example',
            GLOBAL_ISSUER_URL=GLOBAL,
            PROVISIONING_PUBLIC_KEY=self.public,
            PROVISIONING_KEY_ID=KID,
            PROVISIONING_ISSUER=DASHBOARD,
            PROVISIONING_AUDIENCE='',
            PROVISIONING_DEFAULT_REDIRECTS=['https://admin.eu.example'],
        )
        override.enable()
        self.addCleanup(override.disable)
        self.client = APIClient()

    def _token(self, method, path, raw: bytes, **overrides):
        now = unix_now()
        claims = {
            'iss': DASHBOARD,
            'aud': AUDIENCE,
            'sub': 'shellui-dashboard',
            'iat': now,
            'exp': now + 60,
            'jti': uuid.uuid4().hex,
            'scope': 'provisioning',
            'htm': method,
            'htu': path,
            'bh': b64_sha256(raw),
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private, algorithm='RS256', headers={'kid': KID})

    def _call(self, method, path, body=None, *, key='k-1', token=None, **claim_overrides):
        raw = b'' if body is None else json.dumps(body, separators=(',', ':')).encode()
        token = token or self._token(method, path, raw, **claim_overrides)
        headers = {'HTTP_AUTHORIZATION': f'Bearer {token}'}
        if key:
            headers['HTTP_IDEMPOTENCY_KEY'] = key
        return self.client.generic(method, path, raw, content_type='application/json', **headers)

    def _create_body(self, **overrides):
        body = {
            'global_company_id': 'g-1',
            'name': 'Acme',
            'plan': 'free',
            'access_mode': 'public',
            'owner': {'subject': 'sub-1', 'email': 'ada@acme.test', 'email_verified': True, 'name': 'Ada L'},
        }
        body.update(overrides)
        return body

    def _create(self, **overrides):
        return self._call('POST', f'{BASE}/companies', self._create_body(**overrides), key='create:g-1')

    def test_create_company_owner_redirects_without_staff(self):
        response = self._create()
        self.assertEqual(response.status_code, 201, response.content)
        company = Company.objects.get(pk=int(response.json()['id']))
        self.assertEqual(company.access_mode, 'public')
        user = User.objects.get(email='ada@acme.test')
        self.assertFalse(user.is_staff or user.is_superuser)
        self.assertTrue(company.owners.filter(pk=user.pk).exists())
        self.assertTrue(UpstreamAccount.objects.filter(user=user, issuer=GLOBAL, sub='sub-1').exists())
        self.assertTrue(CompanyOAuthRedirect.objects.filter(company=company, base_url='https://admin.eu.example').exists())
        self.assertEqual(response.json()['owners'], [{'subject': 'sub-1'}])

    def test_retry_with_same_key_returns_same_result(self):
        first = self._create()
        second = self._create()
        self.assertEqual(second.status_code, 201)
        self.assertEqual(first.json(), second.json())
        self.assertEqual(Company.objects.count(), 1)

    def test_same_global_id_new_key_is_409_with_id(self):
        first = self._create()
        again = self._call('POST', f'{BASE}/companies', self._create_body(), key='create:other')
        self.assertEqual(again.status_code, 409)
        self.assertEqual(again.json()['id'], first.json()['id'])

    def test_key_reuse_with_different_body_conflicts(self):
        self._create()
        response = self._call('POST', f'{BASE}/companies', self._create_body(name='Other'), key='create:g-1')
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['error_code'], 'idempotency_conflict')

    def test_unverified_owner_creates_nothing(self):
        for flag in (False, 'true', 1, None):
            owner = {'subject': 's', 'email': 'x@acme.test', 'email_verified': flag}
            response = self._call('POST', f'{BASE}/companies', self._create_body(owner=owner), key=f'k-{flag}')
            self.assertEqual(response.status_code, 403)
        self.assertEqual(Company.objects.count(), 0)
        self.assertFalse(User.objects.exists())

    def test_existing_staff_is_refused_and_flags_unchanged(self):
        User.objects.create_user('root', 'ada@acme.test', 'pw', is_staff=True)
        response = self._create()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['error_code'], 'user_is_staff')
        self.assertEqual(Company.objects.count(), 0)
        self.assertTrue(User.objects.get(username='root').is_staff)

    def test_body_staff_fields_are_ignored(self):
        owner = {'subject': 'sub-1', 'email': 'ada@acme.test', 'email_verified': True, 'is_staff': True, 'is_superuser': True}
        self.assertEqual(self._call('POST', f'{BASE}/companies', self._create_body(owner=owner, is_staff=True), key='k').status_code, 201)
        user = User.objects.get(email='ada@acme.test')
        self.assertFalse(user.is_staff or user.is_superuser)

    def test_assertion_checks(self):
        path = f'{BASE}/companies'
        raw = json.dumps(self._create_body(), separators=(',', ':')).encode()
        cases = {
            'wrong issuer': self._token('POST', path, raw, iss='https://evil.example'),
            'wrong audience': self._token('POST', path, raw, aud='id.ch.example'),
            'expired': self._token('POST', path, raw, iat=unix_now() - 400, exp=unix_now() - 200),
            'too long': self._token('POST', path, raw, exp=unix_now() + 3600),
            'wrong method': self._token('PATCH', path, raw),
            'wrong path': self._token('POST', f'{BASE}/companies/1', raw),
            'wrong body': self._token('POST', path, b'{}'),
            'other key': jwt.encode(
                {'iss': DASHBOARD, 'aud': AUDIENCE, 'sub': 's', 'iat': unix_now(), 'exp': unix_now() + 60,
                 'jti': 'j', 'scope': 'provisioning', 'htm': 'POST', 'htu': path, 'bh': b64_sha256(raw)},
                self.other_private, algorithm='RS256', headers={'kid': KID},
            ),
        }
        for label, token in cases.items():
            response = self.client.generic(
                'POST', path, raw, content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}', HTTP_IDEMPOTENCY_KEY='k',
            )
            self.assertEqual(response.status_code, 401, label)
        scope = self._token('POST', path, raw, scope='admin')
        response = self.client.generic(
            'POST', path, raw, content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {scope}', HTTP_IDEMPOTENCY_KEY='k',
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Company.objects.count(), 0)

    def test_replayed_jti_is_rejected(self):
        path = f'{BASE}/companies?linked=shellui'
        token = self._token('GET', path, b'')
        self.assertEqual(self._call('GET', path, token=token, key=None).status_code, 200)
        self.assertEqual(self._call('GET', path, token=token, key=None).status_code, 401)

    def test_write_needs_idempotency_key(self):
        response = self._call('POST', f'{BASE}/companies', self._create_body(), key=None)
        self.assertEqual(response.status_code, 400)

    def test_patch_limits_delete_and_list(self):
        company_id = self._create().json()['id']
        url = f'{BASE}/companies/{company_id}'
        self.assertEqual(self._call('PATCH', url, {'name': 'Acme EU'}, key='rename').json()['name'], 'Acme EU')
        self.assertEqual(self._call('PATCH', url, {'status': 'suspended'}, key='s').json()['status'], 'suspended')
        self.assertEqual(self._call('PATCH', url, {'status': 'active'}, key='a').json()['status'], 'active')
        self.assertEqual(self._call('PATCH', url, {'is_staff': True}, key='x').status_code, 400)
        limits = self._call('PUT', f'{url}/limits', {'version': 2, 'limits': {'max_members': 5}}, key='l2')
        self.assertEqual(limits.status_code, 200)
        self.assertEqual(CompanyPlan.objects.get(company_id=company_id).limits, {'max_members': 5})
        stale = self._call('PUT', f'{url}/limits', {'version': 1, 'limits': {'max_members': 1}}, key='l1')
        self.assertEqual(stale.status_code, 409)
        listed = self._call('GET', f'{BASE}/companies?linked=shellui', key=None).json()
        self.assertEqual(listed['results'][0]['global_company_id'], 'g-1')
        self.assertEqual(listed['results'][0]['limits_version'], 2)
        self.assertIsNone(listed['next'])
        detail = self._call('GET', url, key=None).json()
        self.assertEqual(detail['owners'], [{'subject': 'sub-1'}])
        deleted = self._call('DELETE', url, key='delete:g-1')
        self.assertEqual(deleted.status_code, 202)
        self.assertEqual(ProvisionedCompany.objects.get(company_id=company_id).status, 'deleting')
        self.assertTrue(Company.objects.filter(pk=company_id).exists())
        self.assertEqual(self._call('PATCH', url, {'status': 'active'}, key='a2').status_code, 409)
        self.assertEqual(self._call('GET', f'{BASE}/companies/999', key=None).status_code, 404)

    def test_disabled_without_role_or_key(self):
        for settings in ({'SHELLUI_INSTANCE_ROLE': ''}, {'SHELLUI_INSTANCE_ROLE': 'global'}, {'PROVISIONING_PUBLIC_KEY': ''}):
            with override_settings(**settings):
                for method, path in (('POST', f'{BASE}/companies'), ('GET', f'{BASE}/companies?linked=shellui'),
                                     ('PATCH', f'{BASE}/companies/1'), ('PUT', f'{BASE}/companies/1/limits'),
                                     ('DELETE', f'{BASE}/companies/1')):
                    self.assertEqual(self._call(method, path, {} if method != 'GET' else None).status_code, 404)
