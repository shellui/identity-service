"""Instance roles: standalone stays quiet, provider and relying party stay strict."""

from __future__ import annotations

import uuid
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import jwt
from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import HttpResponse
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework_simplejwt.exceptions import InvalidToken

from apps.actions.registry import company_event_types, is_webhook_event
from apps.authapi.authentication import ShellUIJWTAuthentication
from apps.authapi.jwks import build_jwks_document, generate_rsa_key_pair, load_signing_key
from apps.authapi.models import RefreshTokenSession
from apps.companies.models import Company, CompanyOAuthClient, CompanyOAuthRedirect
from apps.federation.checks import region_production_config, session_cookies_stay_host_only
from apps.federation.models import CompanyPlan, UpstreamAccount, VerifiedEmail
from apps.federation.parsing import region_startup_errors
from apps.federation.session import COOKIE, remember_provider_session, remember_verified_email, set_cookie
from apps.federation.signing import unix_now

User = get_user_model()

ISSUER = 'https://issuer.example'
REGION = 'https://region.example'
REDIRECT = 'https://region.example/oauth/upstream-callback'
CLIENT_ID = 'region-app'
CLIENT_SECRET = 'region-secret-value'


def _rsa():
    private, public = generate_rsa_key_pair(2048)
    signing = load_signing_key(private_pem=private, public_pem=public)
    return signing, build_jwks_document(signing)


class StandalonePathTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_role_defaults_to_standalone(self):
        from django.conf import settings

        self.assertEqual(settings.SHELLUI_INSTANCE_ROLE, '')
        self.assertIsNone(settings.SESSION_COOKIE_DOMAIN)
        self.assertIsNone(settings.CSRF_COOKIE_DOMAIN)

    def test_federation_endpoints_are_absent(self):
        self.assertEqual(self.client.get('/.well-known/openid-configuration').status_code, 404)
        self.assertEqual(self.client.get('/oauth/authorize').status_code, 404)
        self.assertEqual(self.client.post('/oauth/token', {}, format='json').status_code, 404)
        self.assertEqual(self.client.get('/oauth/silent-signin').status_code, 404)
        self.assertEqual(self.client.post('/api/v1/provisioning/companies', {}, format='json').status_code, 404)
        self.assertEqual(self.client.post('/oauth/backchannel-logout', {}).status_code, 404)

    def test_verified_email_and_provider_cookie_stay_off(self):
        user = User.objects.create_user('ada', 'ada@acme.test', 'pw')
        remember_verified_email(user, 'ada@acme.test')
        self.assertFalse(VerifiedEmail.objects.exists())
        request = type('Req', (), {})()
        remember_provider_session(request, user)
        self.assertFalse(hasattr(request, 'federation_op_user_id'))

    def test_federation_events_are_hidden(self):
        ids = {event.id for event in company_event_types()}
        self.assertFalse(any(event_id.startswith('identity.federation.') for event_id in ids))
        self.assertFalse(is_webhook_event('identity.federation.authorize.succeeded'))

    def test_bearer_api_cors_stays_open(self):
        response = self.client.get('/.well-known/jwks.json', HTTP_ORIGIN='https://evil.example')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')

    def test_login_page_has_no_upstream_button(self):
        company = Company.objects.create(name='Acme', slug='acme')
        app = SocialApp.objects.create(provider='github', name='GitHub', client_id='cid', secret='csecret')
        CompanyOAuthClient.objects.create(company=company, social_app=app, is_active=True)
        CompanyOAuthRedirect.objects.create(company=company, base_url='http://127.0.0.1:8765', is_active=True)
        with override_settings(OAUTH_ALLOW_LOOPBACK_REDIRECTS=True, SHELLUI_INSTANCE_ROLE='region'):
            response = self.client.get(
                '/api/v1/authorize',
                {
                    'company_id': company.id,
                    'redirect_to': 'http://127.0.0.1:8765/callback',
                    # Web sign-in requires S256 PKCE.
                    'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                    'code_challenge_method': 'S256',
                },
            )
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('Continue with GitHub', content)
        self.assertNotIn('Continue with Shellui', content)
        self.assertNotIn('silent-signin', content)
        self.assertNotIn('upstream', content)


class _CryptoMixin:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.signing, cls.jwks = _rsa()

    def _enable(self, **extra):
        values = {
            'SHELLUI_INSTANCE_ROLE': 'global',
            'JWT_ISSUER': ISSUER,
            'JWT_AUDIENCE': 'shellui',
            'JWT_SIGNING_KEY': self.signing,
            'JWT_ALGORITHM': 'RS256',
            'JWT_ACTIVE_KEY_ID': self.signing.kid,
            'OIDC_CLIENTS': [
                {
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'redirect_uris': [REDIRECT],
                    'backchannel_logout_uri': 'https://region.example/oauth/backchannel-logout',
                }
            ],
            'OIDC_CORS_ALLOWED_ORIGINS': ['https://app.example.com'],
            'GLOBAL_ISSUER_URL': ISSUER,
            'GLOBAL_JWKS': self.jwks,
            'GLOBAL_CLIENT_ID': CLIENT_ID,
            'GLOBAL_CLIENT_SECRET': CLIENT_SECRET,
        }
        values.update(extra)
        override = override_settings(**values)
        override.enable()
        self.addCleanup(override.disable)

    def _user(self, *, email='ada@acme.test', verified=True, **flags):
        user = User.objects.create_user(email.split('@')[0], email, 'pw', **flags)
        if verified:
            VerifiedEmail.objects.create(user=user, email=email)
        return user

    def _cookie(self, user):
        response = HttpResponse()
        set_cookie(response, user)
        self.client.cookies[COOKIE] = response.cookies[COOKIE].value

    def _sign(self, claims: dict) -> str:
        token = jwt.encode(
            claims,
            self.signing.private_pem,
            algorithm='RS256',
            headers={'kid': self.signing.kid},
        )
        return token.decode() if isinstance(token, bytes) else token


class ProviderTests(_CryptoMixin, TestCase):
    def setUp(self):
        self._enable()
        self.client = APIClient()

    def _authorize(self, **extra):
        params = {
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT,
            'scope': 'openid email profile',
            'state': 'state-1',
            'nonce': 'nonce-1',
            'prompt': 'none',
        }
        params.update(extra)
        return self.client.get('/oauth/authorize', params)

    def test_discovery_and_strict_cors(self):
        open_cors = self.client.get('/.well-known/openid-configuration', HTTP_ORIGIN='https://evil.example')
        self.assertEqual(open_cors.status_code, 200)
        self.assertNotIn('Access-Control-Allow-Origin', open_cors.headers)
        allowed = self.client.get(
            '/.well-known/openid-configuration',
            HTTP_ORIGIN='https://app.example.com',
        )
        self.assertEqual(allowed.headers.get('Access-Control-Allow-Origin'), 'https://app.example.com')
        body = allowed.json()
        self.assertEqual(body['issuer'], ISSUER)
        self.assertEqual(body['prompt_values_supported'], ['none'])
        self.assertTrue(body['backchannel_logout_supported'])
        api = self.client.get('/.well-known/jwks.json', HTTP_ORIGIN='https://evil.example')
        self.assertEqual(api.headers.get('Access-Control-Allow-Origin'), '*')

    def test_prompt_none_without_session_does_not_show_a_login_page(self):
        response = self._authorize()
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlsplit(response['Location']).query)
        self.assertEqual(query['error'], ['login_required'])
        self.assertEqual(query['state'], ['state-1'])
        self.assertNotIn('code', query)
        self.assertNotIn(b'Continue with', response.content)

    def test_prompt_other_than_none_is_refused(self):
        user = self._user()
        self._cookie(user)
        response = self._authorize(prompt='login')
        query = parse_qs(urlsplit(response['Location']).query)
        self.assertEqual(query['error'], ['interaction_required'])

    def test_code_issues_id_token_without_staff_and_replay_fails(self):
        user = self._user(is_staff=True, is_superuser=True)
        self._cookie(user)
        started = self._authorize()
        self.assertEqual(started.status_code, 302)
        code = parse_qs(urlsplit(started['Location']).query)['code'][0]
        token_response = self.client.post(
            '/oauth/token',
            {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
            },
            format='json',
        )
        self.assertEqual(token_response.status_code, 200)
        claims = jwt.decode(
            token_response.json()['id_token'],
            self.signing.public_pem,
            algorithms=['RS256'],
            audience=CLIENT_ID,
            issuer=ISSUER,
        )
        self.assertEqual(claims['sub'], str(user.pk))
        self.assertIs(claims['email_verified'], True)
        self.assertEqual(claims['nonce'], 'nonce-1')
        self.assertNotIn('is_staff', claims)
        self.assertNotIn('is_superuser', claims)
        userinfo = self.client.get(
            '/oauth/userinfo',
            HTTP_AUTHORIZATION=f"Bearer {token_response.json()['access_token']}",
        )
        self.assertEqual(userinfo.status_code, 200)
        self.assertNotIn('is_staff', userinfo.json())
        with override_settings(
            SIMPLE_JWT={
                'ALGORITHM': 'RS256',
                'SIGNING_KEY': self.signing.private_pem,
                'VERIFYING_KEY': self.signing.public_pem,
                'AUDIENCE': 'shellui',
                'ISSUER': ISSUER,
            }
        ):
            with self.assertRaises(InvalidToken):
                ShellUIJWTAuthentication().get_validated_token(token_response.json()['id_token'])
        replay = self.client.post(
            '/oauth/token',
            {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
            },
            format='json',
        )
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.json()['error'], 'invalid_grant')

    def test_unverified_email_is_false_and_wrong_secret_is_rejected(self):
        user = self._user(verified=False)
        self._cookie(user)
        code = parse_qs(urlsplit(self._authorize()['Location']).query)['code'][0]
        denied = self.client.post(
            '/oauth/token',
            {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT,
                'client_id': CLIENT_ID,
                'client_secret': 'nope',
            },
            format='json',
        )
        self.assertEqual(denied.status_code, 401)
        accepted = self.client.post(
            '/oauth/token',
            {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
            },
            format='json',
        )
        self.assertEqual(accepted.status_code, 200)
        claims = jwt.decode(
            accepted.json()['id_token'],
            self.signing.public_pem,
            algorithms=['RS256'],
            audience=CLIENT_ID,
            options={'verify_aud': True},
            issuer=ISSUER,
        )
        self.assertIs(claims['email_verified'], False)

    def test_unknown_redirect_is_not_followed(self):
        response = self._authorize(redirect_uri='https://evil.example/steal')
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('Location', response)

    def test_provider_cookie_is_host_only(self):
        user = self._user()
        response = HttpResponse()
        set_cookie(response, user)
        morsel = response.cookies[COOKIE]
        self.assertEqual(morsel['domain'], '')
        self.assertEqual(morsel['path'], '/oauth/')
        self.assertTrue(morsel['httponly'])

    def test_global_events_are_listed_only_for_that_role(self):
        self.assertTrue(is_webhook_event('identity.federation.authorize.succeeded'))
        ids = {event.id for event in company_event_types()}
        self.assertIn('identity.federation.backchannel_logout.sent', ids)


class RelyingPartyTests(_CryptoMixin, TestCase):
    def setUp(self):
        self._enable(SHELLUI_INSTANCE_ROLE='region', JWT_ISSUER=REGION)
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme')
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://shell.example.com',
            is_active=True,
        )

    def _claims(self, **extra):
        now = unix_now()
        claims = {
            'iss': ISSUER,
            'sub': 'subject-1',
            'aud': CLIENT_ID,
            'exp': now + 300,
            'iat': now,
            'nonce': 'nonce-1',
            'email': 'ada@acme.test',
            'email_verified': True,
            'name': 'Ada Lovelace',
            'is_staff': True,
            'is_superuser': True,
        }
        claims.update(extra)
        return claims

    def _plant(self, nonce='nonce-1'):
        cache.set(
            'federation:rp-state:state-1',
            {
                'nonce': nonce,
                'verifier': 'verifier',
                'company_id': self.company.id,
                'redirect_to': 'https://shell.example.com/done',
                'redirect_uri': REDIRECT,
                'shell_challenge': '',
            },
            timeout=600,
        )

    def test_silent_signin_uses_prompt_none(self):
        response = self.client.get(
            '/oauth/silent-signin',
            {'company_id': self.company.id, 'redirect_to': 'https://shell.example.com/done'},
        )
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlsplit(response['Location']).query)
        self.assertEqual(query['prompt'], ['none'])
        self.assertEqual(query['client_id'], [CLIENT_ID])
        self.assertTrue(response['Location'].startswith(f'{ISSUER}/oauth/authorize?'))

    def test_unverified_email_does_not_create_a_user(self):
        self._plant()
        token = self._sign(self._claims(email_verified=False))
        with patch('apps.federation.relying._exchange', return_value=token):
            response = self.client.get('/oauth/upstream-callback', {'code': 'c', 'state': 'state-1'})
        self.assertEqual(response.status_code, 302)
        self.assertIn('email_not_verified', response['Location'])
        self.assertFalse(User.objects.filter(email='ada@acme.test').exists())

    def test_string_true_is_not_verified(self):
        self._plant()
        token = self._sign(self._claims(email_verified='true'))
        with patch('apps.federation.relying._exchange', return_value=token):
            self.client.get('/oauth/upstream-callback', {'code': 'c', 'state': 'state-1'})
        self.assertFalse(User.objects.filter(email='ada@acme.test').exists())

    def test_wrong_issuer_and_audience_are_rejected(self):
        self._plant()
        for claims in (
            self._claims(iss='https://evil.example'),
            self._claims(aud='other-client'),
        ):
            token = self._sign(claims)
            with patch('apps.federation.relying._exchange', return_value=token):
                response = self.client.get('/oauth/upstream-callback', {'code': 'c', 'state': 'state-1'})
            self.assertEqual(response.status_code, 302)
            self.assertIn('invalid_token', response['Location'])
            self._plant()
        self.assertFalse(User.objects.filter(email='ada@acme.test').exists())

    def test_verified_email_links_a_user_without_staff(self):
        self._plant()
        token = self._sign(self._claims())
        with patch('apps.federation.relying._exchange', return_value=token), patch(
            'apps.authapi.views._finalize_shellui_oauth_login',
            return_value=HttpResponse(status=204),
        ) as finalize:
            response = self.client.get('/oauth/upstream-callback', {'code': 'c', 'state': 'state-1'})
        self.assertEqual(response.status_code, 204)
        user = User.objects.get(email='ada@acme.test')
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        link = UpstreamAccount.objects.get(user=user)
        self.assertEqual(link.issuer, ISSUER)
        self.assertEqual(link.sub, 'subject-1')
        self.assertEqual(finalize.call_args.kwargs['user'].pk, user.pk)

    def test_prompt_none_error_creates_nobody(self):
        self._plant()
        response = self.client.get(
            '/oauth/upstream-callback',
            {'error': 'login_required', 'state': 'state-1'},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn('login_required', response['Location'])
        self.assertEqual(User.objects.count(), 0)

    def test_nonce_mismatch_is_rejected(self):
        self._plant(nonce='expected')
        token = self._sign(self._claims(nonce='other'))
        with patch('apps.federation.relying._exchange', return_value=token):
            response = self.client.get('/oauth/upstream-callback', {'code': 'c', 'state': 'state-1'})
        self.assertIn('invalid_token', response['Location'])
        self.assertEqual(User.objects.count(), 0)


class ProvisioningTests(_CryptoMixin, TestCase):
    def setUp(self):
        self._enable(SHELLUI_INSTANCE_ROLE='region', JWT_ISSUER=REGION)
        self.client = APIClient()

    def _assertion(self, **overrides):
        now = unix_now()
        key = overrides.pop('idempotency_key', 'idem-key-01')
        claims = {
            'iss': ISSUER,
            'aud': REGION,
            'iat': now,
            'nbf': now,
            'exp': now + 60,
            'jti': uuid.uuid4().hex,
            'idempotency_key': key,
            'email_verified': True,
            'company': {'name': 'Acme', 'slug': 'acme'},
            'owner': {
                'email': 'ada@acme.test',
                'name': 'Ada Lovelace',
                'is_staff': True,
                'is_superuser': True,
            },
            'plan': {'max_members': 10},
        }
        claims.update(overrides)
        return self._sign(claims), claims

    def _post(self, token, key, path='/api/v1/provisioning/companies'):
        return self.client.post(
            path,
            {},
            format='json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_IDEMPOTENCY_KEY=key,
        )

    def test_creates_company_owner_and_plan_without_staff(self):
        token, claims = self._assertion()
        response = self._post(token, claims['idempotency_key'])
        self.assertEqual(response.status_code, 200, response.content)
        user = User.objects.get(email='ada@acme.test')
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        company = Company.objects.get(slug='acme')
        self.assertTrue(company.owners.filter(pk=user.pk).exists())
        self.assertTrue(company.memberships.filter(user=user, is_enabled=True).exists())
        self.assertEqual(CompanyPlan.objects.get(company=company).limits, {'max_members': 10})
        self.client.force_authenticate(user=user)
        plan = self.client.get(f'/api/v1/companies/{company.pk}/plan')
        self.assertEqual(plan.status_code, 200)
        self.assertEqual(plan.json()['limits']['max_members'], 10)

    def test_unverified_email_creates_nothing(self):
        for flag in (False, 'true', 1):
            token, claims = self._assertion(email_verified=flag, idempotency_key=f'idem-key-{flag}')
            response = self._post(token, claims['idempotency_key'])
            self.assertEqual(response.status_code, 403, flag)
            self.assertEqual(response.json()['error_code'], 'email_not_verified')
        self.assertEqual(Company.objects.count(), 0)
        self.assertEqual(User.objects.count(), 0)

    def test_replayed_assertion_and_idempotency_key(self):
        token, claims = self._assertion()
        first = self._post(token, claims['idempotency_key'])
        second = self._post(token, claims['idempotency_key'])
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json(), second.json())
        self.assertEqual(Company.objects.count(), 1)
        other, other_claims = self._assertion(jti=claims['jti'], idempotency_key='idem-key-99')
        replay = self._post(other, other_claims['idempotency_key'])
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(replay.json()['error_code'], 'assertion_replayed')
        self.assertEqual(Company.objects.count(), 1)
        fresh, fresh_claims = self._assertion(
            idempotency_key=claims['idempotency_key'],
            company={'name': 'Other', 'slug': 'other'},
        )
        conflict = self._post(fresh, fresh_claims['idempotency_key'])
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()['error_code'], 'idempotency_conflict')
        self.assertFalse(Company.objects.filter(slug='other').exists())

    def test_wrong_issuer_and_audience(self):
        bad_iss, claims = self._assertion(iss='https://evil.example', idempotency_key='idem-key-iss')
        bad_aud, aud_claims = self._assertion(aud='https://other.example', idempotency_key='idem-key-aud')
        self.assertEqual(self._post(bad_iss, claims['idempotency_key']).status_code, 401)
        self.assertEqual(self._post(bad_aud, aud_claims['idempotency_key']).status_code, 401)
        self.assertEqual(Company.objects.count(), 0)

    def test_existing_staff_flag_is_not_changed(self):
        staff = User.objects.create_user('ada', 'ada@acme.test', 'pw', is_staff=True)
        token, claims = self._assertion()
        self.assertEqual(self._post(token, claims['idempotency_key']).status_code, 200)
        staff.refresh_from_db()
        self.assertTrue(staff.is_staff)
        plain = User.objects.create_user('grace', 'grace@acme.test', 'pw', is_staff=False)
        token, claims = self._assertion(
            idempotency_key='idem-key-grace',
            company={'name': 'Globex', 'slug': 'globex'},
            owner={'email': 'grace@acme.test', 'name': 'Grace', 'is_staff': True},
        )
        self.assertEqual(self._post(token, claims['idempotency_key']).status_code, 200)
        plain.refresh_from_db()
        self.assertFalse(plain.is_staff)
        self.assertFalse(plain.is_superuser)

    def test_plan_push_and_member_read(self):
        token, claims = self._assertion()
        claims.pop('plan')
        token = self._sign(claims)
        self.assertEqual(self._post(token, claims['idempotency_key']).status_code, 200)
        now = unix_now()
        plan_claims = {
            'iss': ISSUER,
            'aud': REGION,
            'iat': now,
            'nbf': now,
            'exp': now + 60,
            'jti': uuid.uuid4().hex,
            'idempotency_key': 'idem-plan-01',
            'company_slug': 'acme',
            'plan': {'max_members': 25},
        }
        plan_token = self._sign(plan_claims)
        pushed = self._post(plan_token, 'idem-plan-01', path='/api/v1/provisioning/plans')
        self.assertEqual(pushed.status_code, 200, pushed.content)
        self.assertEqual(CompanyPlan.objects.get(company__slug='acme').limits['max_members'], 25)
        outsider = User.objects.create_user('outsider', 'out@acme.test', 'pw')
        self.client.force_authenticate(user=outsider)
        self.assertEqual(self.client.get(f"/api/v1/companies/{Company.objects.get(slug='acme').pk}/plan").status_code, 404)

    def test_plan_endpoint_is_absent_when_standalone(self):
        user = User.objects.create_user('ada', 'ada@acme.test', 'pw')
        company = Company.objects.create(name='Acme', slug='acme')
        company.members.add(user)
        self.client.force_authenticate(user=user)
        with override_settings(SHELLUI_INSTANCE_ROLE=''):
            self.assertEqual(self.client.get(f'/api/v1/companies/{company.pk}/plan').status_code, 404)


class BackchannelTests(_CryptoMixin, TestCase):
    def setUp(self):
        self._enable(SHELLUI_INSTANCE_ROLE='region', JWT_ISSUER=REGION)
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme')
        self.user = User.objects.create_user('ada', 'ada@acme.test', 'pw')
        UpstreamAccount.objects.create(user=self.user, issuer=ISSUER, sub='subject-1', email=self.user.email)
        self.session = RefreshTokenSession.objects.create(
            user=self.user,
            company=self.company,
            jti='refresh-jti-1',
            family_id=uuid.uuid4(),
            expires_at=timezone.now() + timedelta(days=1),
        )

    def _logout(self, **overrides):
        now = unix_now()
        claims = {
            'iss': ISSUER,
            'sub': 'subject-1',
            'aud': CLIENT_ID,
            'iat': now,
            'exp': now + 60,
            'jti': uuid.uuid4().hex,
            'events': {'http://schemas.openid.net/event/backchannel-logout': {}},
        }
        claims.update(overrides)
        token = self._sign(claims)
        return self.client.post('/oauth/backchannel-logout', {'logout_token': token}, format='json'), claims

    def test_logout_revokes_sessions_and_replay_fails(self):
        response, claims = self._logout()
        self.assertEqual(response.status_code, 200)
        self.session.refresh_from_db()
        self.assertIsNotNone(self.session.revoked_at)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_staff)
        again = self._sign(claims)
        replay = self.client.post('/oauth/backchannel-logout', {'logout_token': again}, format='json')
        self.assertEqual(replay.status_code, 400)

    def test_wrong_audience_and_nonce_are_rejected(self):
        wrong_aud, _claims = self._logout(aud='other-client')
        self.assertEqual(wrong_aud.status_code, 400)
        with_nonce, _claims = self._logout(nonce='n')
        self.assertEqual(with_nonce.status_code, 400)
        self.session.refresh_from_db()
        self.assertIsNone(self.session.revoked_at)


class OutboundTests(_CryptoMixin, TestCase):
    def setUp(self):
        self._enable()
        self.client = APIClient()
        self.staff = User.objects.create_user('ops', 'ops@acme.test', 'pw', is_staff=True)
        VerifiedEmail.objects.create(user=self.staff, email='ops@acme.test')
        self.company = Company.objects.create(name='Ops', slug='ops')

    def test_unverified_owner_is_not_sent(self):
        owner = User.objects.create_user('ada', 'ada@acme.test', 'pw')
        self.client.force_authenticate(user=self.staff)
        with patch('apps.federation.outbound.requests.post') as post:
            response = self.client.post(
                '/api/v1/federation/provision',
                {
                    'region_base_url': 'https://region.example',
                    'audience': REGION,
                    'company_name': 'Acme',
                    'owner_email': owner.email,
                    'idempotency_key': 'idem-key-01',
                },
                format='json',
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['error_code'], 'email_not_verified')
        post.assert_not_called()

    def test_staff_sends_a_signed_assertion(self):
        owner = self.staff
        self.client.force_authenticate(user=self.staff)
        with patch('apps.federation.outbound.requests.post') as post, patch(
            'apps.federation.outbound._reject_private'
        ):
            post.return_value.status_code = 200
            post.return_value.json.return_value = {'company_id': 1}
            response = self.client.post(
                '/api/v1/federation/provision',
                {
                    'region_base_url': 'https://region.example',
                    'audience': REGION,
                    'company_name': 'Acme',
                    'owner_email': owner.email,
                    'idempotency_key': 'idem-key-01',
                    'webhook_company_id': self.company.pk,
                    'plan': {'max_members': 3},
                },
                format='json',
            )
        self.assertEqual(response.status_code, 200, response.content)
        token = post.call_args.kwargs['headers']['Authorization'].split(' ', 1)[1]
        claims = jwt.decode(token, self.signing.public_pem, algorithms=['RS256'], audience=REGION, issuer=ISSUER)
        self.assertIs(claims['email_verified'], True)
        self.assertNotIn('is_staff', claims['owner'])
        self.assertEqual(post.call_args.kwargs['headers']['Idempotency-Key'], 'idem-key-01')


class StartupCheckTests(TestCase):
    def test_region_refuses_default_hosts_only_in_production(self):
        errors = region_startup_errors(
            role='region',
            debug=False,
            email_service_url='https://email.shellui.com',
            csrf_trusted_origins=['https://admin.shellui.com'],
            allowed_hosts=['auth.example.com'],
            issuer_url='https://issuer.example',
            jwks={'keys': [{'kty': 'RSA'}]},
            client_id='app',
            client_secret='secret',
            jwt_issuer='https://region.example',
        )
        self.assertTrue(any('email.shellui.com' in message for message in errors))
        self.assertTrue(any('admin.shellui.com' in message for message in errors))
        self.assertEqual(
            region_startup_errors(
                role='',
                debug=False,
                email_service_url='https://email.shellui.com',
                csrf_trusted_origins=['https://admin.shellui.com'],
                allowed_hosts=['auth.example.com'],
                issuer_url='',
                jwks={'keys': []},
                client_id='',
                client_secret='',
                jwt_issuer=None,
            ),
            [],
        )
        self.assertEqual(
            region_startup_errors(
                role='global',
                debug=False,
                email_service_url='https://email.shellui.com',
                csrf_trusted_origins=['https://admin.shellui.com'],
                allowed_hosts=['id.example.com'],
                issuer_url='',
                jwks={'keys': []},
                client_id='',
                client_secret='',
                jwt_issuer='https://issuer.example',
            ),
            [],
        )
        self.assertEqual(
            region_startup_errors(
                role='region',
                debug=False,
                email_service_url='https://email.example.com',
                csrf_trusted_origins=['https://admin.example.com'],
                allowed_hosts=['auth.example.com'],
                issuer_url='https://issuer.example',
                jwks={'keys': [{'kty': 'RSA'}]},
                client_id='app',
                client_secret='secret',
                jwt_issuer='https://region.example',
            ),
            [],
        )

    def test_cookie_domain_check(self):
        self.assertEqual(session_cookies_stay_host_only(None), [])
        with override_settings(SESSION_COOKIE_DOMAIN='.example.com'):
            errors = session_cookies_stay_host_only(None)
        self.assertEqual(errors[0].id, 'federation.E001')

    def test_deploy_check_passes_for_standalone(self):
        self.assertEqual(region_production_config(None), [])
