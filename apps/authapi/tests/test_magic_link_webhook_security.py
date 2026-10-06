"""Regression tests: the magic-link webhook never carries a sign-in link, and the token is never stored or logged."""

import json
import logging
import re
from contextlib import contextmanager
from unittest.mock import Mock, patch

import jwt
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.actions.delivery import deliver_outbox_row
from apps.actions.handlers.webhook import WebhookDeliveryError
from apps.actions.models import ActionOutbox, DeliveryAttempt, EmailEventOutbox, EventLog
from apps.authapi.magic_link import hash_magic_link_token
from apps.authapi.models import MagicLinkToken
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthRedirect

User = get_user_model()

EVENT = 'identity.auth.magic_link.requested'
_TOKEN_RE = re.compile(r'token=([^&\s]+)')


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record):
        try:
            self.lines.append(record.getMessage())
        except Exception:  # noqa: BLE001
            self.lines.append(str(record.msg))
        if record.exc_info:
            self.lines.append(logging.Formatter().formatException(record.exc_info))


@contextmanager
def _capture_all_logs():
    """Capture every log line at DEBUG, including loggers that do not propagate to root."""
    handler = _ListHandler()
    names = ['', 'django', 'django.request', 'django.security', 'django.server', 'config.request']
    saved = []
    for name in names:
        logger = logging.getLogger(name)
        saved.append((logger, logger.level))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        for logger, level in saved:
            logger.removeHandler(handler)
            logger.setLevel(level)


_BASE_SETTINGS = dict(
    ALLOWED_HOSTS=['testserver'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
    MAGIC_LINK_ENABLED=True,
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    EMAIL_SERVICE_API_KEY='',
)


@override_settings(**_BASE_SETTINGS)
class OwnerMagicLinkTakeoverRegressionTests(TestCase):
    """The review PoC: a company owner must not get a session for another user, nor become staff."""

    def setUp(self):
        cache.clear()
        mail.outbox.clear()
        self.company_b = Company.objects.create(name='Victim Co', slug='victim-co')
        self.staff = User.objects.create_user(username='ops', email='ops@shellui.test', password='x', is_staff=True)
        set_company_access(self.company_b, self.staff, enabled=True)
        self.company_a = Company.objects.create(name='Evil Co', slug='evil-co')
        CompanyOAuthRedirect.objects.create(company=self.company_a, base_url='https://evil.example.com', is_active=True)
        self.attacker = User.objects.create_user(username='mallory', email='m@evil.test', password='x')
        set_company_access(self.company_a, self.attacker, enabled=True)
        self.company_a.owners.add(self.attacker)
        self.owner = APIClient()
        self.owner.force_authenticate(user=self.attacker)
        self.q = f'?company_id={self.company_a.id}'

    def test_owner_cannot_read_link_or_escalate_to_staff(self):
        r = self.owner.post('/api/v1/actions/rules' + self.q, {
            'name': 'grab', 'event_type': EVENT, 'url': 'https://hooks.example.com/grab',
        }, format='json')
        self.assertEqual(r.status_code, 201, r.data)

        anon = APIClient()
        with patch('apps.actions.emit.schedule_outbox_delivery'):
            with self.captureOnCommitCallbacks(execute=True):
                r = anon.post('/api/v1/magic-link/request', {
                    'company_id': self.company_a.id, 'email': 'ops@shellui.test',
                    'redirect_to': 'https://evil.example.com/login/callback',
                }, format='json')
        self.assertEqual(r.status_code, 200, r.data)

        # A staff account gets no sign-in link at all: only the notice, with no token.
        self.assertFalse(MagicLinkToken.objects.exists())
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['ops@shellui.test'])
        self.assertIsNone(_TOKEN_RE.search(mail.outbox[0].body))
        self.assertNotIn('magic-link/verify', mail.outbox[0].body)

        row = ActionOutbox.objects.get(company=self.company_a, event_type=EVENT)
        self.assertNotIn('magic_link_url', row.envelope['data'])
        stored = json.dumps(row.envelope)
        self.assertNotIn('token=', stored)

        detail = self.owner.get(f'/api/v1/actions/deliveries/{row.pk}' + self.q)
        self.assertEqual(detail.status_code, 200)
        body = json.dumps(detail.data, default=str)
        self.assertNotIn('magic_link_url', body)
        self.assertNotIn('magic-link/verify', body)

        # Nothing the owner can read signs anyone in.
        for candidate in (row.envelope['data'].get('request_id'), row.envelope.get('id')):
            r = anon.post(f'/api/v1/magic-link/verify{self.q}',
                          {'token': str(candidate), 'company_id': self.company_a.id}, format='json')
            self.assertEqual(r.status_code, 400)

        # A token issued before this release (or read from provider logs) does not sign staff in.
        from apps.authapi.magic_link import create_magic_link_token

        old_row, raw = create_magic_link_token(
            company=self.company_a, email='ops@shellui.test',
            redirect_to='https://evil.example.com/login/callback', user=self.staff,
        )
        r = anon.post(f'/api/v1/magic-link/verify{self.q}',
                      {'token': raw, 'company_id': self.company_a.id}, format='json')
        self.assertEqual(r.status_code, 403, r.data)
        self.assertEqual(r.data['error_code'], 'magic_link_staff_disabled')
        self.assertNotIn('access_token', r.data)

        # Defense in depth: even a genuine staff session in company A cannot grant is_staff.
        from apps.authapi.views import _issue_shellui_tokens

        set_company_access(self.company_a, self.staff, enabled=True)
        payload = _issue_shellui_tokens(self.staff, company=self.company_a, oauth_provider='google')
        access = payload.get('access_token') or payload.get('access')
        claims = jwt.decode(access, options={'verify_signature': False})
        self.assertEqual(int(claims.get('user_id') or claims.get('sub')), self.staff.pk)
        as_staff = APIClient()
        as_staff.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')
        for body in ({'is_staff': True}, {'is_superuser': True}):
            r = as_staff.put(f'/api/v1/users/{self.attacker.pk}', body, format='json')
            self.assertEqual(r.status_code, 400, r.data)
            self.assertEqual(r.data['error_code'], 'admin_only_field')
        self.attacker.refresh_from_db()
        self.assertFalse(self.attacker.is_staff)
        self.assertFalse(self.attacker.is_superuser)


@override_settings(**_BASE_SETTINGS)
class MagicLinkTokenNeverStoredTests(TestCase):
    def setUp(self):
        cache.clear()
        mail.outbox.clear()
        self.company = Company.objects.create(name='Acme', slug='acme')
        CompanyOAuthRedirect.objects.create(company=self.company, base_url='https://app.example.com', is_active=True)
        self.user = User.objects.create_user(username='ada', email='ada@acme.test', password='x')
        set_company_access(self.company, self.user, enabled=True)
        self.owner_user = User.objects.create_user(username='grace', email='grace@acme.test', password='x')
        set_company_access(self.company, self.owner_user, enabled=True)
        self.company.owners.add(self.owner_user)
        self.owner = APIClient()
        self.owner.force_authenticate(user=self.owner_user)
        self.q = f'?company_id={self.company.id}'
        r = self.owner.post('/api/v1/actions/rules' + self.q, {
            'name': 'notify', 'event_type': EVENT, 'url': 'https://hooks.example.com/notify',
        }, format='json')
        self.assertEqual(r.status_code, 201, r.data)

    def _request(self):
        return APIClient().post('/api/v1/magic-link/request', {
            'company_id': self.company.id, 'email': 'ada@acme.test',
            'redirect_to': 'https://app.example.com/login/callback',
        }, format='json')

    def _assert_absent(self, text: str, raw: str, row_hash: str, where: str) -> None:
        self.assertNotIn(raw, text, where)
        self.assertNotIn(row_hash, text, where)
        self.assertNotIn('magic-link/verify', text, where)

    def test_delivery_records_api_and_admin_never_contain_token(self):
        with patch('apps.actions.emit.schedule_outbox_delivery'):
            with self.captureOnCommitCallbacks(execute=True):
                self.assertEqual(self._request().status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        raw = _TOKEN_RE.search(mail.outbox[0].body).group(1)
        token_row = MagicLinkToken.objects.get(email='ada@acme.test')
        self.assertEqual(token_row.token_hash, hash_magic_link_token(raw))
        outbox = ActionOutbox.objects.get(event_type=EVENT)

        # A receiver that echoes the request body back in an error response.
        def _echo(*, config, envelope, attempt_number=1):
            raise WebhookDeliveryError('HTTP 500', http_status=500, response_excerpt=json.dumps(envelope))

        with patch('apps.actions.delivery.deliver_webhook_action', side_effect=_echo) as deliver:
            deliver_outbox_row(outbox.pk)
        sent = json.dumps(deliver.call_args.kwargs['envelope'])
        self._assert_absent(sent, raw, token_row.token_hash, 'webhook body')

        outbox.refresh_from_db()
        self._assert_absent(json.dumps(outbox.envelope), raw, token_row.token_hash, 'ActionOutbox.envelope')
        self._assert_absent(outbox.last_error, raw, token_row.token_hash, 'ActionOutbox.last_error')
        for attempt in DeliveryAttempt.objects.filter(outbox=outbox):
            self._assert_absent(attempt.error_message, raw, token_row.token_hash, 'DeliveryAttempt')
        for entry in EventLog.objects.filter(event_type=EVENT):
            self._assert_absent(json.dumps(entry.data), raw, token_row.token_hash, 'EventLog')
        for row in EmailEventOutbox.objects.all():
            self._assert_absent(json.dumps(row.body), raw, token_row.token_hash, 'EmailEventOutbox')

        listing = self.owner.get('/api/v1/actions/deliveries' + self.q)
        self.assertEqual(listing.status_code, 200)
        self._assert_absent(json.dumps(listing.data, default=str), raw, token_row.token_hash, 'delivery list API')
        detail = self.owner.get(f'/api/v1/actions/deliveries/{outbox.pk}' + self.q)
        self.assertEqual(detail.status_code, 200)
        self._assert_absent(json.dumps(detail.data, default=str), raw, token_row.token_hash, 'delivery detail API')
        events = self.owner.get('/api/v1/events' + self.q)
        self.assertEqual(events.status_code, 200)
        self._assert_absent(json.dumps(events.data, default=str), raw, token_row.token_hash, 'event log API')

        admin_user = User.objects.create_superuser(username='root', email='root@acme.test', password='x')
        admin_client = self.client_class()
        admin_client.force_login(admin_user)
        page = admin_client.get(reverse('admin:actions_actionoutbox_change', args=[outbox.pk]))
        self.assertEqual(page.status_code, 200)
        self._assert_absent(page.content.decode(), raw, token_row.token_hash, 'Django admin')

        # The only persisted form of the token is its hash on the MagicLinkToken row.
        for field in MagicLinkToken._meta.concrete_fields:
            value = str(getattr(token_row, field.attname))
            self.assertNotIn(raw, value, field.name)

    def test_request_and_verify_never_log_token(self):
        with _capture_all_logs() as logs:
            with patch('apps.actions.emit.schedule_outbox_delivery'):
                with self.captureOnCommitCallbacks(execute=True):
                    self.assertEqual(self._request().status_code, 200)
            raw = _TOKEN_RE.search(mail.outbox[0].body).group(1)
            anon = APIClient()
            page = anon.get(f'/api/v1/magic-link/verify?token={raw}&company_id={self.company.id}',
                            HTTP_REFERER=f'https://mail.example.com/?token={raw}')
            self.assertEqual(page.status_code, 200)
            bad = anon.post(f'/api/v1/magic-link/verify{self.q}',
                            {'token': raw + 'x', 'company_id': self.company.id}, format='json')
            self.assertEqual(bad.status_code, 400)
            good = anon.post(f'/api/v1/magic-link/verify{self.q}',
                             {'token': raw, 'company_id': self.company.id}, format='json',
                             HTTP_REFERER=f'https://auth.example.com/api/v1/magic-link/verify?token={raw}')
            self.assertEqual(good.status_code, 200, good.data)
            again = anon.post(f'/api/v1/magic-link/verify{self.q}',
                              {'token': raw, 'company_id': self.company.id}, format='json')
            self.assertEqual(again.status_code, 400)
        self.assertTrue(logs.lines)
        for line in logs.lines:
            self.assertNotIn(raw, line)

    @override_settings(
        EMAIL_SERVICE_URL='https://email.shellui.com',
        EMAIL_SERVICE_API_KEY='esk_test_identity_key',  # gitleaks:allow
        EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS=0,
    )
    @patch('apps.actions.email_client.requests.post')
    def test_email_service_send_still_happens_with_webhook_rule(self, post):
        response = Mock()
        response.status_code = 202
        response.headers = {}
        response.json.return_value = {'messages': [{'id': 'msg_1', 'status': 'queued'}]}
        post.return_value = response
        with patch('apps.actions.emit.schedule_outbox_delivery'):
            with self.captureOnCommitCallbacks(execute=True):
                self.assertEqual(self._request().status_code, 200)
        send_calls = [c for c in post.call_args_list if c.args[0].endswith('/api/v1/send')]
        self.assertEqual(len(send_calls), 1)
        url = send_calls[0].kwargs['json']['variables']['magic_link_url']
        raw = _TOKEN_RE.search(url).group(1)
        outbox = ActionOutbox.objects.get(event_type=EVENT)
        self.assertNotIn(raw, json.dumps(outbox.envelope))
        self.assertNotIn('magic_link_url', outbox.envelope['data'])
        self.assertFalse(EmailEventOutbox.objects.filter(event_type=EVENT).exists())


@override_settings(**_BASE_SETTINGS)
class TokenRefreshLogTests(TestCase):
    def test_refresh_log_keeps_referer_path_only(self):
        secret = 'S3cretSessionCode_abc123'
        with self.assertLogs('apps.authapi.views', level='INFO') as logs:
            APIClient().post(
                '/api/v1/token?grant_type=refresh_token',
                {'refresh_token': 'not-a-token'},
                format='json',
                HTTP_REFERER=f'https://app.example.com/login/callback?shellui_auth_code={secret}',
            )
        output = '\n'.join(logs.output)
        self.assertIn('referer=https://app.example.com/login/callback', output)
        self.assertNotIn(secret, output)
