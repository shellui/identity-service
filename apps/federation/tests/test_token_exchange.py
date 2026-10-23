"""Token exchange (RFC 8693): a global access token buys a regional session for one company."""

from __future__ import annotations

import jwt
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient

from apps.authapi.models import RefreshTokenSession
from apps.companies.models import Company, CompanyMembership
from apps.federation.exchange import ACCESS_TOKEN_TYPE, GRANT_TYPE
from apps.federation.models import UpstreamAccount
from apps.federation.signing import unix_now
from apps.federation.tests.test_federation import ISSUER, REGION, _CryptoMixin, _rsa

User = get_user_model()
SHELL = 'https://dashboard.example.com'


class TokenExchangeTests(_CryptoMixin, TestCase):
    def setUp(self):
        cache.clear()
        self._enable(
            SHELLUI_INSTANCE_ROLE='region',
            JWT_ISSUER=REGION,
            GLOBAL_ACCESS_TOKEN_AUDIENCE='shellui-global',
            OIDC_CORS_ALLOWED_ORIGINS=[SHELL],
        )
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme')

    def _global_token(self, signing=None, **extra):
        now = unix_now()
        claims = {
            'iss': ISSUER,
            'aud': 'shellui-global',
            'sub': '42',
            'exp': now + 300,
            'iat': now,
            'jti': 'j1',
            'sid': 's1',
            'token_type': 'access',
            'email': 'ada@acme.test',
            'email_verified': True,
            'company_id': 1,
            'user_metadata': {'full_name': 'Ada Lovelace', 'is_staff': True},
        }
        claims.update(extra)
        key = signing or self.signing
        token = jwt.encode(claims, key.private_pem, algorithm='RS256', headers={'kid': key.kid})
        return token.decode() if isinstance(token, bytes) else token

    def _post(self, token, *, company_id=None, origin=SHELL, **extra):
        data = {
            'grant_type': GRANT_TYPE,
            'subject_token': token,
            'subject_token_type': ACCESS_TOKEN_TYPE,
            'company_id': company_id if company_id is not None else self.company.pk,
        }
        data.update(extra)
        headers = {'HTTP_ORIGIN': origin} if origin else {}
        return self.client.post('/oauth/token', data, **headers)

    def _member(self):
        user = User.objects.create_user('ada', 'ada@acme.test')
        UpstreamAccount.objects.create(user=user, issuer=ISSUER, sub='42', email='ada@acme.test')
        CompanyMembership.objects.create(company=self.company, user=user, is_enabled=True)
        return user

    def test_member_gets_a_regional_session(self):
        user = self._member()
        response = self._post(self._global_token())
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body['issued_token_type'], ACCESS_TOKEN_TYPE)
        self.assertEqual(body['token_type'], 'Bearer')
        self.assertTrue(body['refresh_token'])
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertEqual(response['Access-Control-Allow-Origin'], SHELL)
        claims = jwt.decode(body['access_token'], options={'verify_signature': False})
        self.assertEqual(claims['company_id'], self.company.pk)
        self.assertEqual(claims['email'], 'ada@acme.test')
        self.assertFalse(claims['user_metadata']['is_staff'])
        self.assertTrue(RefreshTokenSession.objects.filter(user=user, company=self.company).exists())

    def test_user_without_membership_is_refused_on_an_invite_only_company(self):
        self.company.access_mode = Company.ACCESS_INVITE
        self.company.save(update_fields=['access_mode'])
        response = self._post(self._global_token())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')
        self.assertFalse(CompanyMembership.objects.filter(company=self.company, is_enabled=True).exists())

    def test_bad_tokens_are_refused(self):
        self._member()
        other, _ = _rsa()
        for token in (
            self._global_token(iss='https://evil.example'),
            self._global_token(aud='someone-else'),
            self._global_token(exp=unix_now() - 3600),
            self._global_token(signing=other),
            self._global_token(token_type='refresh'),
            self._global_token(sid=None),
            self._global_token(pat_id='p1'),
            self._global_token(email_verified='true'),
            jwt.encode({'iss': ISSUER, 'sub': '42'}, 'secret', algorithm='HS256'),
        ):
            response = self._post(token)
            self.assertEqual(response.status_code, 400, token)
            self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_local_staff_account_is_not_linked(self):
        User.objects.create_user('root', 'ada@acme.test', is_staff=True)
        response = self._post(self._global_token())
        self.assertEqual(response.status_code, 400)
        self.assertFalse(UpstreamAccount.objects.exists())

    def test_request_shape_and_target(self):
        self._member()
        token = self._global_token()
        self.assertEqual(self._post(token, company_id=999999).json()['error'], 'invalid_target')
        self.assertEqual(
            self._post(token, subject_token_type='urn:ietf:params:oauth:token-type:id_token').status_code, 400
        )
        self.assertEqual(self._post('', company_id=self.company.pk).status_code, 400)

    def test_unknown_origin_is_refused(self):
        self._member()
        response = self._post(self._global_token(), origin='https://evil.example')
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('Access-Control-Allow-Origin', response)

    def test_disabled_without_audience_or_outside_a_region(self):
        self._member()
        with self.settings(GLOBAL_ACCESS_TOKEN_AUDIENCE=''):
            self.assertEqual(self._post(self._global_token()).status_code, 404)
        with self.settings(SHELLUI_INSTANCE_ROLE=''):
            self.assertEqual(self._post(self._global_token()).status_code, 404)

    def test_rate_limited(self):
        with self.settings(AUTH_RATE_LIMITS={'token_exchange': {'limit': 2, 'window': 60}}):
            codes = [self._post('x').status_code for _ in range(3)]
        self.assertEqual(codes[-1], 429)
