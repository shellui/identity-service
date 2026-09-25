import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.actions.models import ActionOutbox, ActionRule
from apps.authapi.magic_link import build_magic_link_verify_url, redeem_magic_link_token
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

    def _request_link(self, email='member@example.com', company=None):
        company = company or self.company
        return self.client.post(
            '/api/v1/magic-link/request',
            {
                'company_id': company.id,
                'email': email,
                'redirect_to': self.redirect_to,
            },
            format='json',
        )

    def test_new_company_defaults_magic_link_enabled(self):
        fresh = Company.objects.create(name='Fresh', slug='fresh-co')
        self.assertTrue(fresh.enable_magic_link)

    def test_settings_lists_magic_link_method(self):
        response = self.client.get(f'/api/v1/settings?company_id={self.company.id}')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['enable_magic_link'])
        self.assertIn('magic_link', response.data['methods'])

    def test_request_and_consume_success(self):
        response = self._request_link()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['ok'])
        row = MagicLinkToken.objects.get(company=self.company, email='member@example.com')
        payload = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': row.token, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(payload.status_code, 200)
        self.assertIn('access_token', payload.data)

        again = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': row.token, 'company_id': self.company.id},
            format='json',
        )
        self.assertEqual(again.status_code, 400)

    def test_expired_token_rejected(self):
        self._request_link()
        row = MagicLinkToken.objects.get(company=self.company)
        row.expires_at = timezone.now() - timedelta(minutes=1)
        row.save(update_fields=['expires_at'])
        response = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': row.token, 'company_id': self.company.id},
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

    def test_action_emit_without_secret_in_envelope(self):
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
        self._request_link()
        outbox = ActionOutbox.objects.filter(event_type='identity.auth.magic_link.requested').first()
        self.assertIsNotNone(outbox)
        data = outbox.envelope['data']
        self.assertIn('request_id', data)
        self.assertIn('expires_at', data)
        self.assertNotIn('token', data)
        self.assertNotIn('magic_link_url', data)
        body = json.dumps(outbox.envelope)
        row = MagicLinkToken.objects.get(pk=data['request_id'])
        self.assertNotIn(row.token, body)

    def test_email_template_context_includes_magic_link_url(self):
        from apps.actions.handlers.email import _email_action_data

        ActionRule.objects.create(
            company=self.company,
            event_type='identity.auth.magic_link.requested',
            action_kind=ActionRule.ACTION_EMAIL,
            enabled=True,
            config={'recipients': ['ops@example.com'], 'include_payload_email': True},
        )
        self._request_link()
        outbox = ActionOutbox.objects.filter(event_type='identity.auth.magic_link.requested').first()
        self.assertIsNotNone(outbox)
        self.assertNotIn('magic_link_url', outbox.envelope.get('data') or {})
        enriched = _email_action_data(outbox.envelope)
        self.assertIn('magic_link_url', enriched)
        self.assertIn('token=', enriched['magic_link_url'])

    def test_build_verify_url_uses_jwt_issuer(self):
        row = MagicLinkToken.objects.create(
            company=self.company,
            email='x@example.com',
            token='abc123',
            redirect_to=self.redirect_to,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        url = build_magic_link_verify_url(token=row.token, company_id=self.company.id)
        self.assertTrue(url.startswith('https://auth.example.com/api/v1/magic-link/verify'))

    def test_redeem_marks_consumed(self):
        row = MagicLinkToken.objects.create(
            company=self.company,
            email='member@example.com',
            user=self.user,
            token='tok',
            redirect_to=self.redirect_to,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        redeemed, err = redeem_magic_link_token(raw_token='tok', company_id=self.company.id)
        self.assertIsNone(err)
        self.assertIsNotNone(redeemed)
        row.refresh_from_db()
        self.assertIsNotNone(row.consumed_at)
