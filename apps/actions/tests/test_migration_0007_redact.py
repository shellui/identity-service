"""Migration actions.0007 removes magic-link sign-in URLs already stored in webhook data."""

import importlib
import json

from django.apps import apps as django_apps
from django.test import TestCase

from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt, EventLog
from apps.companies.models import Company

_migration = importlib.import_module('apps.actions.migrations.0007_redact_magic_link_urls')

EVENT = 'identity.auth.magic_link.requested'
SECRET = 'S3cretMagicToken_abc123'
URL = f'https://auth.example.com/api/v1/magic-link/verify?token={SECRET}&company_id=1'


class RedactMagicLinkUrlsMigrationTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Old Co', slug='old-co')
        self.rule = ActionRule.objects.create(
            company=self.company,
            name='legacy',
            event_type=EVENT,
            config={'url': 'https://hooks.example.com/x', 'secret': 'whsec_test'},
        )

    def _outbox(self, event_type, data, last_error=''):
        return ActionOutbox.objects.create(
            company=self.company,
            action_rule=self.rule,
            event_type=event_type,
            envelope={'id': 'e1', 'type': event_type, 'data': data},
            last_error=last_error,
        )

    def test_redacts_link_from_envelopes_errors_and_attempts(self):
        row = self._outbox(
            EVENT,
            {'request_id': 'r1', 'email': 'ada@acme.test', 'magic_link_url': URL},
            last_error=f'HTTP 500 | body: {json.dumps({"magic_link_url": URL})}',
        )
        attempt = DeliveryAttempt.objects.create(
            outbox=row,
            status=DeliveryAttempt.STATUS_FAILURE,
            attempt_number=1,
            error_message=f'HTTP 500 | body: {{"echo": "{URL}"}}',
        )
        other = self._outbox('identity.user.created', {'user_id': 1, 'note': 'token=keep-me'})
        log = EventLog.objects.create(company=self.company, event_type=EVENT, data={'email': 'a', 'magic_link_url': URL})

        _migration.redact_magic_link_secrets(django_apps, None)

        row.refresh_from_db()
        attempt.refresh_from_db()
        other.refresh_from_db()
        log.refresh_from_db()
        self.assertNotIn('magic_link_url', row.envelope['data'])
        self.assertEqual(row.envelope['data']['email'], 'ada@acme.test')
        for text in (json.dumps(row.envelope), row.last_error, attempt.error_message, json.dumps(log.data)):
            self.assertNotIn(SECRET, text)
        self.assertIn('token=[redacted]', attempt.error_message)
        # Other event types are left alone.
        self.assertEqual(other.envelope['data']['note'], 'token=keep-me')

    def test_is_idempotent_and_reverse_is_noop(self):
        row = self._outbox(EVENT, {'request_id': 'r1'})
        _migration.redact_magic_link_secrets(django_apps, None)
        _migration.redact_magic_link_secrets(django_apps, None)
        row.refresh_from_db()
        self.assertEqual(row.envelope['data'], {'request_id': 'r1'})
        operation = _migration.Migration.operations[0]
        self.assertTrue(operation.reversible)
