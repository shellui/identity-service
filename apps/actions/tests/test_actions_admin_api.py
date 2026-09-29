from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.models import ActionOutbox, ActionRule
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()


@override_settings(ALLOWED_HOSTS=['testserver'])
class ActionsAdminApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme')
        self.owner = User.objects.create_user(username='owner', email='owner@acme.test', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.client.force_authenticate(user=self.owner)

    def _url(self, path: str) -> str:
        return f'{path}?company_id={self.company.id}'

    def test_events_catalog_payload_fields(self):
        response = self.client.get(self._url('/api/v1/actions/events'))
        self.assertEqual(response.status_code, 200)
        row = next(r for r in response.data['results'] if r['type'] == 'identity.user.created')
        self.assertIn('payload_fields', row)
        self.assertNotIn('email_context_fields', row)
        self.assertEqual(row['supported_action_kinds'], ['webhook'])

    def test_create_webhook_rule_with_explicit_secret(self):
        response = self.client.post(
            self._url('/api/v1/actions/rules'),
            {
                'name': 'n8n',
                'event_type': 'identity.user.created',
                'url': 'https://hooks.example.com/user',
                'secret': 'whsec_test',
            },
            format='json',
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['action_kind'], 'webhook')
        self.assertTrue(response.data['config']['has_secret'])
        self.assertEqual(response.data['config']['secret_hint'], 'test')
        self.assertEqual(response.data['secret'], 'whsec_test')
        self.assertNotIn('secret', response.data['config'])

    def test_create_webhook_rule_auto_generates_secret(self):
        for payload in (
            {
                'name': 'n8n auto',
                'event_type': 'identity.user.created',
                'url': 'https://hooks.example.com/auto',
            },
            {
                'name': 'n8n blank',
                'event_type': 'identity.user.created',
                'url': 'https://hooks.example.com/blank',
                'secret': '   ',
            },
        ):
            with self.subTest(payload=payload['name']):
                response = self.client.post(
                    self._url('/api/v1/actions/rules'),
                    payload,
                    format='json',
                )
                self.assertEqual(response.status_code, 201, response.data)
                secret = response.data['secret']
                self.assertTrue(secret.startswith('whsec_'))
                self.assertTrue(response.data['config']['has_secret'])
                self.assertEqual(response.data['config']['secret_hint'], secret[-4:])
                self.assertNotIn('secret', response.data['config'])

        secret = response.data['secret']
        self.assertTrue(secret.startswith('whsec_'))
        self.assertTrue(response.data['config']['has_secret'])
        self.assertEqual(response.data['config']['secret_hint'], secret[-4:])
        self.assertNotIn('secret', response.data['config'])

        rule = ActionRule.objects.get(pk=response.data['id'])
        self.assertEqual(rule.config['secret'], secret)

        listed = self.client.get(self._url('/api/v1/actions/rules'))
        row = next(r for r in listed.data['results'] if r['id'] == rule.pk)
        self.assertNotIn('secret', row)
        self.assertNotIn('secret', row['config'])

    def test_rotate_webhook_secret(self):
        rule = ActionRule.objects.create(
            company=self.company,
            name='Hook',
            event_type='identity.user.created',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 'whsec_oldsecretvalue'},
        )
        detail = self.client.get(self._url(f'/api/v1/actions/rules/{rule.pk}'))
        self.assertEqual(detail.status_code, 200)

        response = self.client.post(self._url(f'/api/v1/actions/rules/{rule.pk}/rotate-secret'))
        self.assertEqual(response.status_code, 200)
        new_secret = response.data['secret']
        self.assertTrue(new_secret.startswith('whsec_'))
        self.assertNotEqual(new_secret, 'whsec_oldsecretvalue')
        self.assertNotIn('rule', response.data)
        self.assertNotIn('secret', detail.data)
        for key in (
            'id',
            'company_id',
            'name',
            'description',
            'event_type',
            'enabled',
            'action_kind',
            'created_at',
        ):
            self.assertEqual(response.data[key], detail.data[key], key)
        self.assertEqual(response.data['config']['url'], detail.data['config']['url'])
        self.assertTrue(response.data['config']['has_secret'])
        self.assertNotIn('secret', response.data['config'])
        rule.refresh_from_db()
        self.assertEqual(rule.config['secret'], new_secret)

    def test_list_deliveries_and_requeue(self):
        rule = ActionRule.objects.create(
            company=self.company,
            name='Hook',
            event_type='identity.user.created',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        row = ActionOutbox.objects.create(
            company=self.company,
            action_rule=rule,
            event_type='identity.user.created',
            envelope={'id': '1', 'type': 'identity.user.created', 'data': {}},
            status=ActionOutbox.STATUS_DEAD,
            last_error='fail',
        )
        listed = self.client.get(self._url('/api/v1/actions/deliveries'))
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.data['count'], 1)

        detail = self.client.get(self._url(f'/api/v1/actions/deliveries/{row.pk}'))
        self.assertEqual(detail.status_code, 200)
        self.assertIn('attempts', detail.data)

        requeue = self.client.post(self._url(f'/api/v1/actions/deliveries/{row.pk}/requeue'))
        self.assertEqual(requeue.status_code, 200)
        self.assertEqual(requeue.data['status'], 'pending')

    @patch('apps.actions.webhook_test_send.deliver_webhook_action')
    def test_send_test_webhook(self, mock_deliver):
        rule = ActionRule.objects.create(
            company=self.company,
            name='Hook',
            event_type='identity.user.created',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        response = self.client.post(self._url(f'/api/v1/actions/rules/{rule.pk}/send-test'))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['ok'])
        mock_deliver.assert_called_once()
