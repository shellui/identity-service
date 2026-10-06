"""The sign-in email goes to the address that asked for it, and to no one else.

A company owner must not receive another person's magic link: not through an email
rule on email-service, not as a copy, and not through the event forwarding queue.
"""

import json
import re
from unittest.mock import Mock, patch

import requests
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.email_events import _event_payload, build_event_body
from apps.actions.models import ActionRule, EmailEventOutbox, EventLog
from apps.actions.registry import get_event_type
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthRedirect

User = get_user_model()

EVENT = 'identity.auth.magic_link.requested'
_TOKEN_RE = re.compile(r'token=([^&\s"]+)')
# Not a live credential. gitleaks:allow
_API_KEY = 'esk_test_identity_key'  # gitleaks:allow


def _accepted():
    response = Mock()
    response.status_code = 202
    response.headers = {}
    response.json.return_value = {'idempotent_replay': False, 'rule_enabled': True, 'messages': []}
    return response


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
    MAGIC_LINK_ENABLED=True,
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    EMAIL_SERVICE_URL='https://email.shellui.com',
    EMAIL_SERVICE_API_KEY=_API_KEY,
    EMAIL_SERVICE_SEND_ATTEMPTS=1,
    EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS=0,
    ACTIONS_WEBHOOK_SYNC_DELIVERY=False,
)
class MagicLinkRecipientTests(TestCase):
    def setUp(self):
        cache.clear()
        mail.outbox.clear()
        self.company = Company.objects.create(name='Evil Co', slug='evil-co-mail')
        CompanyOAuthRedirect.objects.create(company=self.company, base_url='https://app.evil.example', is_active=True)
        self.owner = User.objects.create_user(username='mallory', email='owner@evil.example', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.staff = User.objects.create_user(username='ops', email='ops@shellui.test', password='x', is_staff=True)
        set_company_access(self.company, self.staff, enabled=True)
        # The owner subscribed everything they can to the event.
        ActionRule.objects.create(
            company=self.company,
            name='grab',
            event_type=EVENT,
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://hooks.example.com/grab'},
            enabled=True,
        )

    def _request(self, email='ops@shellui.test'):
        with patch('apps.actions.emit.schedule_outbox_delivery'):
            with self.captureOnCommitCallbacks(execute=True):
                return APIClient().post(
                    '/api/v1/magic-link/request',
                    {
                        'company_id': self.company.id,
                        'email': email,
                        'redirect_to': 'https://app.evil.example/login/callback',
                    },
                    format='json',
                )

    @patch('apps.actions.email_client.requests.post')
    def test_only_the_requesting_address_gets_the_link(self, post):
        post.return_value = _accepted()
        self.assertEqual(self._request().status_code, 200)
        sends = [call for call in post.call_args_list if call.args[0].endswith('/api/v1/send')]
        self.assertEqual(len(sends), 1)
        body = sends[0].kwargs['json']
        self.assertEqual([item['email'] for item in body['to']], ['ops@shellui.test'])
        self.assertFalse({'cc', 'bcc', 'reply_to', 'recipients', 'headers'} & set(body))
        raw = _TOKEN_RE.search(body['variables']['magic_link_url']).group(1)
        others = [call for call in post.call_args_list if not call.args[0].endswith('/api/v1/send')]
        for call in others:
            self.assertNotIn(raw, json.dumps(call.kwargs.get('json')))
            self.assertNotIn('owner@evil.example', json.dumps(call.kwargs.get('json')))
        self.assertFalse(EmailEventOutbox.objects.filter(event_type=EVENT).exists())
        for row in EmailEventOutbox.objects.all():
            self.assertNotIn(raw, json.dumps(row.body))
        logged = EventLog.objects.get(event_type=EVENT)
        self.assertNotIn(raw, json.dumps(logged.data))

    @patch('apps.actions.email_client.requests.post')
    def test_smtp_fallback_has_one_recipient_and_no_copies(self, post):
        post.side_effect = requests.ConnectionError('down')
        self.assertEqual(self._request().status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, ['ops@shellui.test'])
        self.assertEqual((message.cc, message.bcc, message.reply_to), ([], [], []))
        self.assertTrue(_TOKEN_RE.search(message.body))

    def test_magic_link_event_is_never_forwarded_for_email_rules(self):
        event = get_event_type(EVENT)
        payload = {
            'email': 'ops@shellui.test',
            'magic_link_url': 'https://auth.example.com/api/v1/magic-link/verify?token=secret',
            'token': 'secret',
            'raw_token': 'secret',
            'request_id': '1',
        }
        self.assertIsNone(build_event_body(event, self.company, payload, event_log_id=1))
        # Without an email the hints would be the company owners. Still nothing is forwarded.
        self.assertIsNone(build_event_body(event, self.company, {'magic_link_url': payload['magic_link_url']}, event_log_id=2))
        self.assertIsNone(build_event_body(get_event_type('identity.user.invited'), self.company, {'email': 'x@y.z'}, event_log_id=3))
        forwarded = _event_payload(event, self.company, payload)
        self.assertFalse({'magic_link_url', 'token', 'raw_token'} & set(forwarded))
        self.assertNotIn('secret', json.dumps(forwarded))
