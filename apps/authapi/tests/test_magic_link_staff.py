"""Staff accounts never sign in with a magic link.

A company that sends mail through its own provider can read every sign-in link in
that provider's logs. So a staff (``is_staff``) or superuser account gets no token
and no link: it gets a notice without a link instead, through the same built-in
auth path. The public API answers exactly as for any other address.
"""

from __future__ import annotations

import json
import re
from importlib import import_module
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import requests
from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.actions.models import ActionOutbox, ActionRule, EventLog
from apps.authapi.magic_link import create_magic_link_token, sign_in_page_url
from apps.authapi.models import MagicLinkToken
from apps.authapi.tests.test_oauth_google_id_token_callback import GoogleIdTokenCallbackTests, _google_mock_routes
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthRedirect

User = get_user_model()

EVENT = 'identity.auth.magic_link.requested'
STAFF_TEMPLATE = 'identity.auth.magic_link.staff_blocked'
REDIRECT_TO = 'https://app.example.com/login/callback'
_TOKEN_RE = re.compile(r'token=([^&\s"]+)')
_API_KEY = 'esk_test_identity_key'  # gitleaks:allow


def _response(status, body):
    response = Mock()
    response.status_code = status
    response.headers = {}
    response.json.return_value = body
    response.text = json.dumps(body)
    response.content = response.text.encode()
    return response


def _accepted():
    return _response(202, {'idempotent_replay': False, 'messages': []})


_SETTINGS = dict(
    ALLOWED_HOSTS=['testserver'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
    MAGIC_LINK_ENABLED=True,
    MAGIC_LINK_TTL_SECONDS=900,
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    EMAIL_SERVICE_API_KEY='',
    ACTIONS_WEBHOOK_SYNC_DELIVERY=False,
)


class _Base(TestCase):
    def setUp(self):
        cache.clear()
        mail.outbox.clear()
        self.company = Company.objects.create(name='Acme', slug='acme-ml')
        CompanyOAuthRedirect.objects.create(company=self.company, base_url='https://app.example.com', is_active=True)
        self.member = User.objects.create_user(username='ada', email='ada@acme.test', password='x')
        self.staff = User.objects.create_user(username='ops', email='ops@shellui.test', password='pw-staff', is_staff=True)
        self.superuser = User.objects.create_user(
            username='root', email='root@shellui.test', password='pw-root', is_superuser=True
        )
        for user in (self.member, self.staff, self.superuser):
            set_company_access(self.company, user, enabled=True)
        ActionRule.objects.create(
            company=self.company,
            name='notify',
            event_type=EVENT,
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://hooks.example.com/notify'},
            enabled=True,
        )

    def _request(self, email, **extra):
        body = {'company_id': self.company.id, 'email': email, 'redirect_to': REDIRECT_TO}
        body.update(extra)
        with patch('apps.actions.emit.schedule_outbox_delivery'):
            with self.captureOnCommitCallbacks(execute=True):
                return APIClient().post('/api/v1/magic-link/request', body, format='json')


@override_settings(**_SETTINGS)
class StaffMagicLinkRequestTests(_Base):
    def test_staff_and_superuser_get_no_token_and_a_notice_without_link(self):
        for user in (self.staff, self.superuser):
            with self.subTest(user=user.username):
                mail.outbox.clear()
                response = self._request(user.email)
                self.assertEqual(response.status_code, 200, response.data)
                self.assertFalse(MagicLinkToken.objects.filter(email=user.email).exists())
                self.assertEqual(len(mail.outbox), 1)
                message = mail.outbox[0]
                self.assertEqual(message.to, [user.email])
                self.assertEqual((message.cc, message.bcc, message.reply_to), ([], [], []))
                self.assertEqual(message.subject, '[Shellui] Sign in to Acme with your password or SSO')
                html = message.alternatives[0][0]
                for body in (message.body, html, message.subject):
                    self.assertIsNone(_TOKEN_RE.search(body))
                    self.assertNotIn('magic-link/verify', body)
                    self.assertNotIn('auth.example.com', body)
                self.assertIn('No sign-in link for staff accounts', message.body)
                self.assertIn("staff accounts can't sign in with an email link", message.body)
                self.assertIn('Go to sign-in: https://app.example.com/', message.body)
                self.assertIn('href="https://app.example.com/"', html)

    def test_french_notice(self):
        self._request(self.staff.email, language='fr')
        message = mail.outbox[0]
        self.assertEqual(message.subject, '[Shellui] Connectez-vous à Acme avec votre mot de passe ou le SSO')
        self.assertIn('Pas de lien de connexion pour les comptes staff', message.body)

    def test_staff_is_matched_by_address_case_insensitively(self):
        response = self._request('OPS@Shellui.Test')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(MagicLinkToken.objects.exists())
        self.assertEqual(mail.outbox[0].to, ['ops@shellui.test'])
        self.assertIsNone(_TOKEN_RE.search(mail.outbox[0].body))

    def test_api_response_is_the_same_for_staff_member_and_unknown_addresses(self):
        answers = []
        for email in (self.staff.email, self.superuser.email, self.member.email, 'nobody@acme.test'):
            response = self._request(email)
            answers.append((response.status_code, json.loads(response.content), sorted(response.headers.keys())))
        self.assertEqual(len({json.dumps(answer, sort_keys=True) for answer in answers}), 1, answers)

    def test_non_staff_still_gets_a_magic_link(self):
        response = self._request(self.member.email)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MagicLinkToken.objects.filter(email=self.member.email).count(), 1)
        self.assertTrue(_TOKEN_RE.search(mail.outbox[0].body))

    def test_webhook_notification_does_not_reveal_staff(self):
        self._request(self.member.email)
        self._request(self.staff.email)
        rows = {
            row.envelope['data']['email']: row
            for row in ActionOutbox.objects.filter(company=self.company, event_type=EVENT)
        }
        self.assertEqual(set(rows), {self.member.email, self.staff.email})
        member_data = rows[self.member.email].envelope['data']
        staff_data = rows[self.staff.email].envelope['data']
        self.assertEqual(sorted(member_data), sorted(staff_data))
        self.assertEqual(staff_data['source'], 'magic_link')
        self.assertEqual(staff_data['user_id'], self.staff.pk)
        dumped = json.dumps(rows[self.staff.email].envelope).lower()
        for word in ('staff', 'superuser', 'blocked', 'token='):
            self.assertNotIn(word, dumped.replace('ops@shellui.test', ''))
        logged = list(EventLog.objects.filter(event_type=EVENT).order_by('pk'))
        self.assertEqual(len(logged), 2)
        self.assertEqual(sorted(logged[0].data), sorted(logged[1].data))

    def test_unused_tokens_of_staff_are_deleted_on_request(self):
        # A token left from before the account became staff (signals bypassed).
        member = User.objects.create_user(username='late', email='late@shellui.test', password='x')
        old, _raw = create_magic_link_token(company=self.company, email=member.email, redirect_to=REDIRECT_TO, user=member)
        User.objects.filter(pk=member.pk).update(is_staff=True)
        self._request(member.email)
        self.assertFalse(MagicLinkToken.objects.filter(pk=old.pk).exists())

    def test_loopback_redirect_gives_no_sign_in_link(self):
        with override_settings(DEBUG=False):
            self.assertIsNone(sign_in_page_url('http://127.0.0.1:8765/callback'))
            self.assertIsNone(sign_in_page_url('https://localhost/callback'))
            self.assertIsNone(sign_in_page_url('http://app.example.com/'))
            self.assertEqual(sign_in_page_url('https://user:pw@app.example.com/x?y=1'), 'https://app.example.com/')


@override_settings(
    **{
        **_SETTINGS,
        'EMAIL_SERVICE_URL': 'https://email.shellui.com',
        'EMAIL_SERVICE_API_KEY': _API_KEY,
        'EMAIL_SERVICE_SEND_ATTEMPTS': 1,
        'EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS': 0,
    }
)
class StaffNoticeEmailServiceTests(_Base):
    @patch('apps.actions.email_client.requests.post')
    def test_notice_goes_through_send_with_the_builtin_template(self, post):
        post.return_value = _accepted()
        response = self._request(self.staff.email)
        self.assertEqual(response.status_code, 200)
        sends = [call for call in post.call_args_list if call.args[0].endswith('/api/v1/send')]
        self.assertEqual(len(sends), 1)
        body = sends[0].kwargs['json']
        self.assertEqual(body['template_key'], STAFF_TEMPLATE)
        self.assertEqual(body['to'], [{'email': self.staff.email, 'user_id': self.staff.pk}])
        self.assertEqual(body['variables'], {'company_name': 'Acme', 'sign_in_url': 'https://app.example.com/'})
        self.assertTrue(body['idempotency_key'].startswith(f'magic-link-staff-{self.company.pk}-'))
        self.assertFalse({'cc', 'bcc', 'reply_to', 'recipients', 'headers'} & set(body))
        self.assertNotIn('token', json.dumps(body))
        self.assertEqual(mail.outbox, [])
        self.assertFalse(MagicLinkToken.objects.exists())

    @patch('apps.actions.email_client.requests.post')
    def test_unknown_template_falls_back_to_smtp(self, post):
        post.return_value = _response(404, {'error_code': 'template_not_found'})
        response = self._request(self.staff.email)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.staff.email])
        self.assertIsNone(_TOKEN_RE.search(mail.outbox[0].body))

    @patch('apps.actions.email_client.requests.post')
    def test_refusals_map_the_same_way_as_for_other_addresses(self, post):
        for refusal, expected in (
            (_response(422, {'error_code': 'recipient_suppressed'}), (422, 'recipient_suppressed')),
            (_response(429, {'error_code': 'recipient_rate_limited'}), (429, 'recipient_rate_limited')),
        ):
            post.return_value = refusal
            for email in (self.member.email, self.staff.email):
                with self.subTest(email=email, code=expected[1]):
                    cache.clear()
                    response = self._request(email)
                    self.assertEqual((response.status_code, response.data.get('error_code')), expected)
        self.assertFalse(MagicLinkToken.objects.exists())

    @patch('apps.actions.email_client.requests.post')
    def test_unreachable_service_uses_smtp_without_link(self, post):
        post.side_effect = requests.ConnectionError('down')
        self.assertEqual(self._request(self.staff.email).status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIsNone(_TOKEN_RE.search(mail.outbox[0].body))


@override_settings(**_SETTINGS)
class StaffMagicLinkVerifyTests(_Base):
    def _token(self, user=None, email=None):
        _row, raw = create_magic_link_token(
            company=self.company,
            email=email or user.email,
            redirect_to=REDIRECT_TO,
            user=user,
        )
        return raw

    def _make_staff_quietly(self, user, **flags):
        """Like a role change that skips signals (queryset update), so the token survives."""
        User.objects.filter(pk=user.pk).update(**(flags or {'is_staff': True}))
        user.refresh_from_db()

    def test_json_verify_rejects_a_staff_token_with_a_stable_code(self):
        raw = self._token(self.member)
        self._make_staff_quietly(self.member)
        response = APIClient().post(
            f'/api/v1/magic-link/verify?company_id={self.company.id}',
            {'token': raw, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(response.status_code, 403, response.data)
        self.assertEqual(response.data['error_code'], 'magic_link_staff_disabled')
        self.assertNotIn('access_token', response.data)
        self.assertIsNotNone(MagicLinkToken.objects.get().consumed_at)
        failure = EventLog.objects.filter(event_type='identity.auth.login.failed').latest('pk')
        self.assertEqual(failure.data.get('failure_reason'), 'magic_link_staff_disabled')

    def test_superuser_token_rejected(self):
        raw = self._token(self.member)
        self._make_staff_quietly(self.member, is_superuser=True)
        response = APIClient().post(
            f'/api/v1/magic-link/verify?company_id={self.company.id}',
            {'token': raw, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error_code'], 'magic_link_staff_disabled')

    def test_token_for_a_new_address_is_rejected_once_a_staff_account_has_it(self):
        raw = self._token(None, email='new@shellui.test')
        staff = User.objects.create_user(username='new', email='new@shellui.test', password='x')
        User.objects.filter(pk=staff.pk).update(is_staff=True)
        response = APIClient().post(
            f'/api/v1/magic-link/verify?company_id={self.company.id}',
            {'token': raw, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error_code'], 'magic_link_staff_disabled')

    def test_browser_post_redirects_with_the_error_code(self):
        raw = self._token(self.member)
        self._make_staff_quietly(self.member)
        response = Client().post(
            f'/api/v1/magic-link/verify?company_id={self.company.id}',
            {'token': raw, 'company_id': self.company.id},
        )
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response['Location'])
        self.assertEqual(f'{location.scheme}://{location.netloc}{location.path}', REDIRECT_TO)
        query = parse_qs(location.query)
        self.assertEqual(query['shellui_oauth_error_code'], ['magic_link_staff_disabled'])
        self.assertNotIn('code', query)
        self.assertNotIn('access_token', response['Location'])

    def test_get_page_explains_and_does_not_submit(self):
        raw = self._token(self.member)
        self._make_staff_quietly(self.member)
        response = Client().get(f'/api/v1/magic-link/verify?token={raw}&company_id={self.company.id}')
        self.assertEqual(response.status_code, 403)
        page = response.content.decode()
        self.assertIn('Sign-in links are off for staff accounts', page)
        self.assertIn("staff accounts can&#x27;t sign in with an email link", page)
        self.assertIn('href="https://app.example.com/"', page)
        self.assertIn('data-error-code="magic_link_staff_disabled"', page)
        self.assertNotIn('<form', page)
        self.assertNotIn(raw, page)
        self.assertIsNone(MagicLinkToken.objects.get().consumed_at)

    def test_get_page_in_french(self):
        raw = self._token(self.member)
        self._make_staff_quietly(self.member)
        response = Client().get(
            f'/api/v1/magic-link/verify?token={raw}&company_id={self.company.id}',
            HTTP_ACCEPT_LANGUAGE='fr-CH,fr;q=0.9,en;q=0.8',
        )
        page = response.content.decode()
        self.assertIn('<html lang="fr">', page)
        self.assertIn('Les liens de connexion sont désactivés pour les comptes staff', page)
        self.assertIn('Aller à la connexion', page)

    def test_non_staff_token_still_signs_in(self):
        raw = self._token(self.member)
        response = APIClient().post(
            f'/api/v1/magic-link/verify?company_id={self.company.id}',
            {'token': raw, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data.get('access_token') or response.data.get('access'))


@override_settings(**_SETTINGS)
class StaffTokenInvalidationTests(_Base):
    def test_becoming_staff_deletes_unused_tokens(self):
        for flag in ('is_staff', 'is_superuser'):
            with self.subTest(flag=flag):
                user = User.objects.create_user(username=f'u-{flag}', email=f'{flag}@acme.test', password='x')
                unused, _ = create_magic_link_token(company=self.company, email=user.email, redirect_to=REDIRECT_TO, user=user)
                by_address, _ = create_magic_link_token(company=self.company, email=user.email.upper(), redirect_to=REDIRECT_TO)
                used, _ = create_magic_link_token(company=self.company, email=user.email, redirect_to=REDIRECT_TO, user=user)
                MagicLinkToken.objects.filter(pk=used.pk).update(consumed_at=timezone.now())
                other, _ = create_magic_link_token(company=self.company, email=self.member.email, redirect_to=REDIRECT_TO, user=self.member)
                setattr(user, flag, True)
                user.save()
                self.assertFalse(MagicLinkToken.objects.filter(pk__in=[unused.pk, by_address.pk]).exists())
                self.assertTrue(MagicLinkToken.objects.filter(pk=used.pk).exists())
                self.assertTrue(MagicLinkToken.objects.filter(pk=other.pk).exists())

    def test_becoming_staff_in_django_admin_deletes_unused_tokens(self):
        operator = User.objects.create_user(
            username='operator', email='operator@shellui.test', password='x', is_staff=True, is_superuser=True
        )
        admin = Client()
        admin.force_login(operator)
        token, _ = create_magic_link_token(company=self.company, email=self.member.email, redirect_to=REDIRECT_TO, user=self.member)
        page = admin.get(f'/admin/auth/user/{self.member.pk}/change/')
        self.assertEqual(page.status_code, 200)
        form = page.context['adminform'].form
        data = {}
        for name, field in form.fields.items():
            value = form.initial.get(name, field.initial)
            if value is None:
                continue
            if isinstance(value, (list, tuple)) or hasattr(value, 'all'):
                values = value.all() if hasattr(value, 'all') else value
                data[name] = [getattr(item, 'pk', item) for item in values]
            elif hasattr(value, 'isoformat'):
                continue
            else:
                data[name] = value
        data.pop('password', None)
        data['is_staff'] = 'on'
        data['is_active'] = 'on'
        response = admin.post(f'/admin/auth/user/{self.member.pk}/change/', data)
        self.assertIn(response.status_code, (200, 302))
        self.member.refresh_from_db()
        self.assertTrue(self.member.is_staff, getattr(response, 'context', None) and response.context.get('errors'))
        self.assertFalse(MagicLinkToken.objects.filter(pk=token.pk).exists())

    def test_migration_deletes_unused_staff_tokens(self):
        migration = import_module('apps.authapi.migrations.0017_delete_staff_magic_link_tokens')
        member_token, _ = create_magic_link_token(company=self.company, email=self.member.email, redirect_to=REDIRECT_TO, user=self.member)
        staff_by_user, _ = create_magic_link_token(company=self.company, email='alias@acme.test', redirect_to=REDIRECT_TO, user=self.staff)
        staff_by_email, _ = create_magic_link_token(company=self.company, email='ROOT@shellui.test', redirect_to=REDIRECT_TO)
        staff_used, _ = create_magic_link_token(company=self.company, email=self.staff.email, redirect_to=REDIRECT_TO, user=self.staff)
        MagicLinkToken.objects.filter(pk=staff_used.pk).update(consumed_at=timezone.now())
        migration.delete_staff_tokens(django_apps, None)
        remaining = set(MagicLinkToken.objects.values_list('pk', flat=True))
        self.assertEqual(remaining, {member_token.pk, staff_used.pk})


@override_settings(**_SETTINGS)
class StaffOtherSignInMethodsTests(_Base):
    def test_staff_password_login_in_django_admin_still_works(self):
        response = Client().post('/admin/login/?next=/admin/', {'username': 'ops', 'password': 'pw-staff', 'next': '/admin/'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/admin/')


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    OAUTH_ALLOW_LOOPBACK_REDIRECTS=True,
    AUTH_RATE_LIMIT_ENABLED=False,
    OAUTH_TOKEN_DELIVERY='code',
    OAUTH_SKIP_CONFIRM_PROVIDERS=['google'],
)
class StaffOAuthLoginTests(TestCase):
    """Reuses the Google callback harness with a staff account."""

    setUp = GoogleIdTokenCallbackTests.setUp
    _callback_with_routes = GoogleIdTokenCallbackTests._callback_with_routes

    def test_staff_oauth_login_still_works(self):
        User.objects.filter(pk=self.existing.pk).update(is_staff=True, is_superuser=True)
        routes, hostnames, _token = _google_mock_routes(
            client_id=self.client_id,
            signing=self.signing,
            sub='google-sub-staff',
            email='user-google@example.com',
            issuer='https://accounts.google.com',
        )
        response = self._callback_with_routes(routes, hostnames)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].startswith('https://shell.example.com/login/callback'))
        self.assertNotIn('shellui_oauth_error', response['Location'])
        success = EventLog.objects.filter(event_type='identity.auth.login.succeeded').latest('pk')
        self.assertTrue(success.data.get('is_staff_at_event'))
