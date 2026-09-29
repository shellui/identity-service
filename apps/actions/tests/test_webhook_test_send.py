import uuid
from unittest.mock import patch

from django.test import TestCase

from apps.actions.models import ActionRule
from apps.actions.webhook_test_send import send_webhook_test_for_rule
from apps.companies.models import Company


class WebhookTestSendSampleDataTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme')

    @patch('apps.actions.webhook_test_send.deliver_webhook_action')
    def test_consecutive_test_sends_use_distinct_request_ids(self, mock_deliver):
        rule = ActionRule.objects.create(
            company=self.company,
            name='Magic link hook',
            event_type='identity.auth.magic_link.requested',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        send_webhook_test_for_rule(rule=rule, company=self.company)
        first_envelope = mock_deliver.call_args.kwargs['envelope']
        send_webhook_test_for_rule(rule=rule, company=self.company)
        second_envelope = mock_deliver.call_args.kwargs['envelope']

        first_request_id = first_envelope['data']['request_id']
        second_request_id = second_envelope['data']['request_id']
        self.assertNotEqual(first_request_id, second_request_id)
        uuid.UUID(first_request_id)
        uuid.UUID(second_request_id)
        self.assertNotEqual(first_envelope['id'], second_envelope['id'])
