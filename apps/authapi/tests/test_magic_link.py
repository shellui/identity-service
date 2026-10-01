import json
import re
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from django.core import mail

from apps.actions.models import ActionOutbox, ActionRule
from apps.authapi.magic_link import (
    build_magic_link_verify_url,
    create_magic_link_token,
    hash_magic_link_token,
    redeem_magic_link_token,
)
from apps.authapi.models import MagicLinkToken
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthRedirect

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
    MAGIC_LINK_TTL_SECONDS=900,
    MAGIC_LINK_ENABLED=True,
)
class MagicLinkAuthTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.company = Company.objects.create(name='Magic Co', slug='magic-co')
        self.assertTrue(self.company.enable_magic_link)
        CompanyOAuthRedirect.objects.create(
            company=self.company,
            base_url='https://app.example.com',
            is_active=True,
        )
        self.redirect_to = 'https://app.example.com/login/callback'
        self.user = User.objects.create_user(
            username='member',
            email='member@example.com',
            password='unused',
        )
        set_company_access(self.company, self.user, enabled=True)

    def _request_link(self, email='member@example.com', company=None, **extra_headers):
        company = company or self.company
        return self.client.post(
            '/api/v1/magic-link/request',
            {
                'company_id': company.id,
                'email': email,
                'redirect_to': self.redirect_to,
            },
            format='json',
            **extra_headers,
        )

    def _raw_token_from_email(self) -> str:
        body = mail.outbox[0].body
        match = re.search(r'token=([^&\s]+)', body)
        self.assertIsNotNone(match)
        return match.group(1)

    def test_new_company_defaults_magic_link_enabled(self):
        fresh = Company.objects.create(name='Fresh', slug='fresh-co')
        self.assertTrue(fresh.enable_magic_link)

    def test_settings_lists_magic_link_method(self):
        response = self.client.get(f'/api/v1/settings?company_id={self.company.id}')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['enable_magic_link'])
        self.assertIn('magic_link', response.data['methods'])

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_request_and_consume_success(self):
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            response = self._request_link()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['ok'])
        raw = self._raw_token_from_email()
        payload = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': raw, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(payload.status_code, 200)
        self.assertIn('access_token', payload.data)

        again = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': raw, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(again.status_code, 400)

    def test_expired_token_rejected(self):
        raw = 'expired-raw-token'
        MagicLinkToken.objects.create(
            company=self.company,
            email='member@example.com',
            token_hash=hash_magic_link_token(raw),
            redirect_to=self.redirect_to,
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        response = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': raw, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(response.status_code, 400)

    @override_settings(MAGIC_LINK_ENABLED=False)
    def test_global_disable_returns_403(self):
        response = self._request_link()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error_code'], 'magic_link_disabled')

    def test_company_disable_returns_403(self):
        self.company.enable_magic_link = False
        self.company.save(update_fields=['enable_magic_link'])
        response = self._request_link()
        self.assertEqual(response.status_code, 403)

    @override_settings(AUTH_RATE_LIMIT_ENABLED=True, AUTH_RATE_LIMITS={'magic_link': {'limit': 1, 'window': 60}})
    def test_rate_limit_on_request(self):
        first = self._request_link()
        self.assertEqual(first.status_code, 200)
        second = self._request_link()
        self.assertEqual(second.status_code, 429)

    @override_settings(
        AUTH_RATE_LIMIT_ENABLED=True,
        AUTH_RATE_LIMITS={'magic_link': {'limit': 10, 'window': 60}},
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
        TRUSTED_PROXY_IPS=('127.0.0.1',),
    )
    def test_other_ip_not_blocked_after_many_company_requests(self):
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            for i in range(10):
                response = self._request_link(
                    email=f'random{i}@example.com',
                    HTTP_X_FORWARDED_FOR='1.2.3.4',
                )
                self.assertEqual(response.status_code, 200, response.data)
        response = self._request_link(
            email='member@example.com',
            HTTP_X_FORWARDED_FOR='5.6.7.8',
        )
        self.assertEqual(response.status_code, 200, response.data)

    def test_action_emit_includes_magic_link_url(self):
        ActionRule.objects.create(
            company=self.company,
            event_type='identity.auth.magic_link.requested',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={
                'url': 'https://hooks.example.com/magic',
                'secret': 'whsec_test',
            },
        )
        with self.captureOnCommitCallbacks(execute=True):
            with patch(
                'apps.authapi.magic_link_views.send_magic_link_email',
                return_value=None,
            ) as send_email:
                self._request_link()
        send_email.assert_not_called()
        outbox = ActionOutbox.objects.filter(event_type='identity.auth.magic_link.requested').first()
        self.assertIsNotNone(outbox)
        data = outbox.envelope['data']
        self.assertIn('request_id', data)
        self.assertIn('expires_at', data)
        self.assertNotIn('token', data)
        self.assertIn('magic_link_url', data)
        url = data['magic_link_url']
        self.assertTrue(url.startswith('https://auth.example.com/api/v1/magic-link/verify?'))
        self.assertIn(f'company_id={self.company.id}', url)
        raw = re.search(r'token=([^&]+)', url).group(1)
        row = MagicLinkToken.objects.get(pk=data['request_id'])
        self.assertEqual(row.token_hash, hash_magic_link_token(raw))
        body = json.dumps(outbox.envelope)
        self.assertNotIn(row.token_hash, body)

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_email_sent_when_magic_link_webhook_rule_disabled(self):
        ActionRule.objects.create(
            company=self.company,
            event_type='identity.auth.magic_link.requested',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=False,
            config={
                'url': 'https://hooks.example.com/magic',
                'secret': 'whsec_test',
            },
        )
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            self._request_link()
        self.assertEqual(len(mail.outbox), 1)
        self.assertFalse(ActionOutbox.objects.filter(event_type='identity.auth.magic_link.requested').exists())

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_email_sent_when_webhook_emit_fails(self):
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            with patch(
                'apps.authapi.magic_link_views.emit_magic_link_requested',
                side_effect=RuntimeError('boom'),
            ):
                self._request_link()
        self.assertEqual(len(mail.outbox), 1)

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_plaintext_email_link_contains_unescaped_company_id(self):
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            self._request_link()
        body = mail.outbox[0].body
        self.assertIn('&company_id=', body)
        self.assertNotIn('&amp;company_id=', body)
        self.assertNotIn('&amp;company_id=', mail.outbox[0].subject)

    def test_get_verify_does_not_consume_token(self):
        row, raw = create_magic_link_token(
            company=self.company,
            email='member@example.com',
            redirect_to=self.redirect_to,
            user=self.user,
        )
        response = self.client.get(
            '/api/v1/magic-link/verify',
            {'token': raw, 'company_id': self.company.id},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Continue sign-in', response.content)
        row.refresh_from_db()
        self.assertIsNone(row.consumed_at)

    def test_webhook_omits_user_id_without_company_membership(self):
        outsider = User.objects.create_user(
            username='outsider',
            email='outsider@example.com',
            password='unused',
        )
        ActionRule.objects.create(
            company=self.company,
            event_type='identity.auth.magic_link.requested',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={'url': 'https://hooks.example.com/magic', 'secret': 'whsec_test'},
        )
        with self.captureOnCommitCallbacks(execute=True):
            with patch(
                'apps.authapi.magic_link_views.send_magic_link_email',
                return_value=None,
            ):
                self.client.post(
                    '/api/v1/magic-link/request',
                    {
                        'company_id': self.company.id,
                        'email': outsider.email,
                        'redirect_to': self.redirect_to,
                    },
                    format='json',
                )
        outbox = ActionOutbox.objects.filter(event_type='identity.auth.magic_link.requested').first()
        self.assertIsNotNone(outbox)
        data = outbox.envelope['data']
        self.assertNotIn('user_id', data)

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_magic_link_request_sends_email(self):
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            self._request_link()
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ['member@example.com'])
        self.assertIn('Sign in', msg.subject)
        raw = self._raw_token_from_email()
        self.assertIn('token=', msg.body)
        self.assertIn(raw, msg.body)
        self.assertEqual(len(msg.alternatives), 1)
        html_part, mime = msg.alternatives[0]
        self.assertEqual(mime, 'text/html')
        self.assertIn('token=', html_part)
        self.assertIn(raw, html_part)
        row = MagicLinkToken.objects.get(company=self.company, email='member@example.com')
        self.assertEqual(row.token_hash, hash_magic_link_token(raw))

    def test_build_verify_url_uses_jwt_issuer(self):
        url = build_magic_link_verify_url(token='abc123', company_id=self.company.id)
        self.assertTrue(url.startswith('https://auth.example.com/api/v1/magic-link/verify'))

    def test_redeem_marks_consumed(self):
        row, raw = create_magic_link_token(
            company=self.company,
            email='member@example.com',
            redirect_to=self.redirect_to,
            user=self.user,
        )
        redeemed, err = redeem_magic_link_token(raw_token=raw, company_id=self.company.id)
        self.assertIsNone(err)
        self.assertIsNotNone(redeemed)
        row.refresh_from_db()
        self.assertIsNotNone(row.consumed_at)

    def test_double_redeem_returns_already_used(self):
        _row, raw = create_magic_link_token(
            company=self.company,
            email='member@example.com',
            redirect_to=self.redirect_to,
            user=self.user,
        )
        first, err1 = redeem_magic_link_token(raw_token=raw, company_id=self.company.id)
        self.assertIsNone(err1)
        self.assertIsNotNone(first)
        second, err2 = redeem_magic_link_token(raw_token=raw, company_id=self.company.id)
        self.assertIsNone(second)
        self.assertEqual(err2, 'Magic link already used.')

    def test_token_hash_stored_not_plaintext(self):
        row, raw = create_magic_link_token(
            company=self.company,
            email='member@example.com',
            redirect_to=self.redirect_to,
        )
        self.assertEqual(row.token_hash, hash_magic_link_token(raw))
        self.assertFalse(MagicLinkToken.objects.filter(token_hash=raw).exists())
