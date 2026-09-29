import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.actions.delivery import backoff_seconds, claim_next_pending_outbox, deliver_outbox_row
from apps.actions.emit import emit_event
from apps.actions.handlers.webhook import WebhookDeliveryError
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt
from apps.actions.ssrf import SSRFError, validate_webhook_url
from apps.actions.webhook_signing import encode_webhook_envelope, sign_webhook_body
from apps.actions.webhook_transport import WebhookPostResult
from apps.companies.models import Company

User = get_user_model()


@override_settings(ACTIONS_WEBHOOK_SYNC_DELIVERY=True)
class EmitEventTests(TestCase):
    def setUp(self):
        self.company_a = Company.objects.create(name='A', slug='co-a')
        self.company_b = Company.objects.create(name='B', slug='co-b')
        ActionRule.objects.create(
            company=self.company_a,
            name='Hook',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/hook', 'secret': 'whsec_test'},
        )

    def test_unknown_event_type_raises(self):
        with self.assertRaises(ValueError):
            emit_event('not.real', self.company_a, {})

    def test_no_rules_returns_empty(self):
        rows = emit_event(
            'identity.scim.user.provisioned',
            self.company_b,
            {'user_id': 1},
        )
        self.assertEqual(rows, [])
        self.assertEqual(ActionOutbox.objects.count(), 0)

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=WebhookPostResult(status=200, excerpt=''))
    def test_emit_creates_outbox_and_delivers_on_commit(self, _mock_post):
        with self.captureOnCommitCallbacks(execute=True):
            rows = emit_event(
                'identity.scim.user.provisioned',
                self.company_a,
                {'user_id': 9, 'email': 'ada@a.test', 'source': 'scim'},
            )
        self.assertEqual(len(rows), 1)
        row = ActionOutbox.objects.get(pk=rows[0].pk)
        self.assertEqual(row.status, ActionOutbox.STATUS_DELIVERED)

    def test_company_isolation(self):
        emit_event('identity.scim.user.provisioned', self.company_b, {'user_id': 1})
        self.assertEqual(ActionOutbox.objects.count(), 0)

    def test_emit_by_default_false_skips_without_force(self):
        ActionRule.objects.create(
            company=self.company_a,
            name='Updated',
            event_type='identity.user.updated',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 'x'},
        )
        rows = emit_event('identity.user.updated', self.company_a, {'user_id': 1})
        self.assertEqual(rows, [])
        self.assertEqual(ActionOutbox.objects.count(), 0)


class WebhookHandlerTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Hook Co', slug='hook-co')
        self.rule = ActionRule.objects.create(
            company=self.company,
            name='n8n',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={
                'url': 'https://example.com/hook',
                'secret': 'whsec_test',
            },
        )

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=WebhookPostResult(status=200, excerpt=''))
    def test_webhook_posts_signed_json(self, mock_post):
        envelope = {
            'id': 'evt-1',
            'type': 'identity.scim.user.provisioned',
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': self.company.pk, 'slug': 'hook-co', 'name': 'Hook Co'},
            'data': {'user_id': 1},
        }
        row = ActionOutbox.objects.create(
            company=self.company,
            action_rule=self.rule,
            event_type=envelope['type'],
            envelope=envelope,
        )
        deliver_outbox_row(row.pk)
        mock_post.assert_called_once()
        _args, kwargs = mock_post.call_args
        self.assertEqual(kwargs['body'], encode_webhook_envelope(envelope))
        headers = kwargs['headers']
        self.assertIn('webhook-signature', headers)
        self.assertIn('webhook-id', headers)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_DELIVERED)

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=WebhookPostResult(status=500, excerpt='err'))
    def test_webhook_failure_records_attempt(self, mock_post):
        row = ActionOutbox.objects.create(
            company=self.company,
            action_rule=self.rule,
            event_type='identity.scim.user.provisioned',
            envelope={'id': 'x', 'type': 'identity.scim.user.provisioned', 'data': {}},
        )
        deliver_outbox_row(row.pk)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_FAILED)
        self.assertIsNotNone(row.next_attempt_at)
        attempt = DeliveryAttempt.objects.get(outbox=row)
        self.assertEqual(attempt.http_status, 500)
        self.assertIn('HTTP 500', attempt.error_message)

    def test_ssrf_blocks_private_ip(self):
        with self.assertRaises(SSRFError):
            validate_webhook_url('http://127.0.0.1/hook')
        with self.assertRaises(WebhookDeliveryError):
            from apps.actions.handlers.webhook import deliver_webhook_action

            deliver_webhook_action(
                config={'url': 'http://127.0.0.1/hook', 'secret': 'x'},
                envelope={'id': '1', 'type': 't', 'data': {}},
            )


class BackoffTests(TestCase):
    def test_backoff_sequence(self):
        self.assertEqual(backoff_seconds(1), 30)
        self.assertEqual(backoff_seconds(2), 60)
        self.assertEqual(backoff_seconds(3), 120)
        self.assertEqual(backoff_seconds(10), 3600)


@override_settings(ACTIONS_OUTBOX_MAX_ATTEMPTS=3)
class RetryDeliveryTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Drain', slug='drain-co')
        self.rule = ActionRule.objects.create(
            company=self.company,
            name='hook',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=WebhookPostResult(status=500, excerpt=''))
    def test_dead_after_max_attempts(self, _mock):
        row = ActionOutbox.objects.create(
            company=self.company,
            action_rule=self.rule,
            event_type='identity.scim.user.provisioned',
            envelope={'id': '1', 'type': 'identity.scim.user.provisioned', 'data': {}},
        )
        for _ in range(3):
            deliver_outbox_row(row.pk)
            row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_DEAD)


class RetryCommandTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Retry Co', slug='retry-co')
        self.rule = ActionRule.objects.create(
            company=self.company,
            name='hook',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=WebhookPostResult(status=200, excerpt=''))
    def test_retry_command_processes_batch(self, _mock):
        ActionOutbox.objects.create(
            company=self.company,
            action_rule=self.rule,
            event_type='identity.scim.user.provisioned',
            envelope={'id': '1', 'type': 'identity.scim.user.provisioned', 'data': {}},
            status=ActionOutbox.STATUS_FAILED,
            next_attempt_at=timezone.now(),
        )
        call_command('retry_webhooks', batch_size=10, max_seconds=5, concurrency=1)
        row = ActionOutbox.objects.get()
        self.assertEqual(row.status, ActionOutbox.STATUS_DELIVERED)

    def test_dry_run_claims_without_http(self):
        row = ActionOutbox.objects.create(
            company=self.company,
            action_rule=self.rule,
            event_type='identity.scim.user.provisioned',
            envelope={'id': '1', 'type': 'identity.scim.user.provisioned', 'data': {}},
            status=ActionOutbox.STATUS_PENDING,
        )
        with patch('apps.actions.delivery.deliver_outbox_row') as mock_deliver:
            call_command('retry_webhooks', batch_size=5, dry_run=True)
            mock_deliver.assert_not_called()
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_PENDING)

    def test_skip_locked_claim(self):
        row = ActionOutbox.objects.create(
            company=self.company,
            action_rule=self.rule,
            event_type='identity.scim.user.provisioned',
            envelope={'id': '1', 'type': 'identity.scim.user.provisioned', 'data': {}},
            status=ActionOutbox.STATUS_FAILED,
            next_attempt_at=timezone.now(),
            locked_until=timezone.now() + timedelta(minutes=5),
        )
        claimed = claim_next_pending_outbox()
        self.assertIsNone(claimed)
        row.refresh_from_db()
        self.assertIsNotNone(row.locked_until)

    def test_stale_lease_reclaimed(self):
        row = ActionOutbox.objects.create(
            company=self.company,
            action_rule=self.rule,
            event_type='identity.scim.user.provisioned',
            envelope={'id': '1', 'type': 'identity.scim.user.provisioned', 'data': {}},
            status=ActionOutbox.STATUS_FAILED,
            next_attempt_at=timezone.now(),
            locked_until=timezone.now() - timedelta(seconds=30),
        )
        claimed = claim_next_pending_outbox()
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed.pk, row.pk)


class WebhookSigningTests(TestCase):
    def test_signature_format(self):
        body = b'{"ok":true}'
        headers = sign_webhook_body(secret='secret', body=body, webhook_id='id-1')
        self.assertTrue(headers['webhook-signature'].startswith('v1,'))


@override_settings(SCIM_ENABLED=True, ALLOWED_HOSTS=['testserver'], ACTIONS_WEBHOOK_SYNC_DELIVERY=True)
class ScimActionIntegrationTests(TestCase):
    def setUp(self):
        from django.test import Client

        from apps.scim.models import CompanyScimToken
        from apps.scim.tokens import generate_scim_token

        self.client = Client()
        self.company = Company.objects.create(name='Acme', slug='acme')
        ActionRule.objects.create(
            company=self.company,
            name='Provision hook',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 'sec'},
        )
        raw, prefix, digest = generate_scim_token()
        self.scim_token = raw
        CompanyScimToken.objects.create(
            company=self.company,
            token_prefix=prefix,
            token_hash=digest,
        )

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=WebhookPostResult(status=200, excerpt=''))
    def test_scim_user_create_triggers_action(self, _mock):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'scim-user@acme.com',
            'emails': [{'value': 'scim-user@acme.com', 'primary': True}],
            'active': True,
        }
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                f'/api/v1/companies/{self.company.pk}/scim/v2/Users',
                data=json.dumps(payload),
                content_type='application/scim+json',
                HTTP_AUTHORIZATION=f'Bearer {self.scim_token}',
            )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(ActionOutbox.objects.filter(company=self.company).count(), 1)


class ActionAdminFormTests(TestCase):
    def test_blank_secret_keeps_existing_on_edit(self):
        from apps.actions.admin_forms import ActionRuleAdminForm

        company = Company.objects.create(name='F', slug='form-co')
        rule = ActionRule.objects.create(
            company=company,
            name='Hook',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 'keep-me', 'authorization_header': 'Bearer x'},
        )

        class SuperuserForm(ActionRuleAdminForm):
            is_superuser = True

        form = SuperuserForm(
            data={
                'company': company.pk,
                'name': 'Hook',
                'description': '',
                'enabled': True,
                'event_type': 'identity.scim.user.provisioned',
                'action_kind': ActionRule.ACTION_WEBHOOK,
                'webhook_url': 'https://example.com/h',
                'webhook_secret': '',
                'webhook_authorization_header': '',
            },
            instance=rule,
        )
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        self.assertEqual(saved.config['secret'], 'keep-me')
        self.assertEqual(saved.config['authorization_header'], 'Bearer x')


class ActionAdminTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Admin Co', slug='admin-co')
        self.staff = User.objects.create_superuser(
            username='staff',
            email='staff@test.com',
            password='secret',
        )

    def test_action_rule_admin_loads(self):
        from django.test import Client

        client = Client()
        client.force_login(self.staff)
        url = reverse('admin:actions_actionrule_add')
        response = client.get(url)
        self.assertEqual(response.status_code, 200)

    @patch('apps.actions.admin.messages.success')
    @patch('apps.actions.delivery.deliver_outbox_row')
    def test_retry_admin_action_requeues_without_inline_delivery(self, mock_deliver, _mock_msg):
        from django.contrib.admin.sites import AdminSite
        from django.test import RequestFactory

        from apps.actions.admin import ActionOutboxAdmin

        rule = ActionRule.objects.create(
            company=self.company,
            name='Hook',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        row = ActionOutbox.objects.create(
            company=self.company,
            action_rule=rule,
            event_type='identity.scim.user.provisioned',
            envelope={'id': '1', 'type': 'identity.scim.user.provisioned', 'data': {}},
            status=ActionOutbox.STATUS_FAILED,
            last_error='nope',
        )
        request = RequestFactory().get('/admin/')
        request.user = self.staff
        admin = ActionOutboxAdmin(ActionOutbox, AdminSite())
        admin.retry_selected_deliveries(request, ActionOutbox.objects.filter(pk=row.pk))
        mock_deliver.assert_not_called()
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_PENDING)
        self.assertEqual(row.last_error, '')
