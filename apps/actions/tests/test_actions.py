import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.actions.delivery import deliver_outbox_row
from apps.actions.html_plain import html_to_plain_text
from apps.actions.emit import emit_event
from apps.actions.handlers.webhook import WebhookDeliveryError
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt
from apps.actions.ssrf import SSRFError, validate_webhook_url
from apps.actions.webhook_signing import sign_webhook_body
from apps.companies.models import Company

User = get_user_model()

LOC_MEM_EMAIL = {
    'EMAIL_BACKEND': 'django.core.mail.backends.locmem.EmailBackend',
}


class EmitEventTests(TestCase):
    def setUp(self):
        self.company_a = Company.objects.create(name='A', slug='co-a')
        self.company_b = Company.objects.create(name='B', slug='co-b')
        ActionRule.objects.create(
            company=self.company_a,
            name='Notify',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['ops@a.test']},
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

    @override_settings(**LOC_MEM_EMAIL)
    def test_emit_creates_outbox_and_delivers_on_commit(self):
        with self.captureOnCommitCallbacks(execute=True):
            rows = emit_event(
                'identity.scim.user.provisioned',
                self.company_a,
                {'user_id': 9, 'email': 'ada@a.test', 'source': 'scim'},
            )
        self.assertEqual(len(rows), 1)
        row = ActionOutbox.objects.get(pk=rows[0].pk)
        self.assertEqual(row.status, ActionOutbox.STATUS_DELIVERED)
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertIn('ada@a.test', msg.subject)
        self.assertEqual(msg.to, ['ops@a.test'])
        self.assertTrue(msg.body.strip())
        self.assertEqual(len(msg.alternatives), 1)
        html_part, mime = msg.alternatives[0]
        self.assertEqual(mime, 'text/html')
        self.assertIn('Shellui identity', html_part)

    def test_company_isolation(self):
        emit_event('identity.scim.user.provisioned', self.company_b, {'user_id': 1})
        self.assertEqual(ActionOutbox.objects.count(), 0)

    def test_emit_by_default_false_skips_without_force(self):
        ActionRule.objects.create(
            company=self.company_a,
            name='Updated',
            event_type='identity.user.updated',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['ops@a.test']},
        )
        rows = emit_event('identity.user.updated', self.company_a, {'user_id': 1})
        self.assertEqual(rows, [])
        self.assertEqual(ActionOutbox.objects.count(), 0)

    @override_settings(**LOC_MEM_EMAIL)
    def test_include_payload_email_adds_recipient(self):
        ActionRule.objects.filter(company=self.company_a).update(
            config={'recipients': ['ops@a.test'], 'include_payload_email': True},
        )
        with self.captureOnCommitCallbacks(execute=True):
            emit_event(
                'identity.scim.user.provisioned',
                self.company_a,
                {'user_id': 3, 'email': 'user@a.test', 'source': 'scim'},
            )
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(mail.outbox[-2].to, ['ops@a.test'])
        self.assertEqual(mail.outbox[-1].to, ['user@a.test'])


@override_settings(**LOC_MEM_EMAIL)
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

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=200)
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
        self.assertEqual(kwargs['body'], json.dumps(envelope, separators=(',', ':'), sort_keys=True).encode())
        headers = kwargs['headers']
        self.assertIn('webhook-signature', headers)
        self.assertIn('webhook-id', headers)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_DELIVERED)

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=500)
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
        self.assertEqual(DeliveryAttempt.objects.filter(outbox=row).count(), 1)

    def test_ssrf_blocks_private_ip(self):
        with self.assertRaises(SSRFError):
            validate_webhook_url('http://127.0.0.1/hook')
        with self.assertRaises(WebhookDeliveryError):
            from apps.actions.handlers.webhook import deliver_webhook_action

            deliver_webhook_action(
                config={'url': 'http://127.0.0.1/hook', 'secret': 'x'},
                envelope={'id': '1', 'type': 't', 'data': {}},
            )


class DrainCommandTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Drain', slug='drain-co')
        self.rule = ActionRule.objects.create(
            company=self.company,
            name='mail',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['d@drain.test']},
        )

    @override_settings(**LOC_MEM_EMAIL, ACTIONS_OUTBOX_MAX_ATTEMPTS=3)
    @patch('apps.actions.delivery.deliver_email_action', side_effect=RuntimeError('boom'))
    def test_drain_retries_until_dead(self, _mock):
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
        call_command('drain_action_outbox', batch_size=10)


class HtmlPlainTextTests(TestCase):
    def test_html_to_plain_preserves_link_text(self):
        plain = html_to_plain_text(
            '<p>See <a href="https://example.com/docs">the docs</a> for details.</p>'
        )
        self.assertIn('the docs', plain)
        self.assertIn('https://example.com/docs', plain)
        self.assertNotIn('<p>', plain)


class WebhookSigningTests(TestCase):
    def test_signature_format(self):
        body = b'{"ok":true}'
        headers = sign_webhook_body(secret='secret', body=body, webhook_id='id-1')
        self.assertTrue(headers['webhook-signature'].startswith('v1,'))


@override_settings(
    **LOC_MEM_EMAIL,
    SCIM_ENABLED=True,
    ALLOWED_HOSTS=['testserver'],
)
class ScimActionIntegrationTests(TestCase):
    def setUp(self):
        from django.test import Client

        from apps.scim.models import CompanyScimToken
        from apps.scim.tokens import generate_scim_token

        self.client = Client()
        self.company = Company.objects.create(name='Acme', slug='acme')
        ActionRule.objects.create(
            company=self.company,
            name='Provision email',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['admin@acme.test']},
        )
        raw, prefix, digest = generate_scim_token()
        self.scim_token = raw
        CompanyScimToken.objects.create(
            company=self.company,
            token_prefix=prefix,
            token_hash=digest,
        )

    def test_scim_user_create_triggers_action(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'scim-user@acme.com',
            'emails': [{'value': 'scim-user@acme.com', 'primary': True}],
            'active': True,
        }
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                '/api/v1/companies/acme/scim/v2/Users',
                data=json.dumps(payload),
                content_type='application/scim+json',
                HTTP_AUTHORIZATION=f'Bearer {self.scim_token}',
            )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(ActionOutbox.objects.filter(company=self.company).count(), 1)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['admin@acme.test'])


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

    def test_non_superuser_cannot_persist_allow_private_urls(self):
        from apps.actions.admin_forms import ActionRuleAdminForm

        company = Company.objects.create(name='G', slug='gate-co')
        class StaffForm(ActionRuleAdminForm):
            is_superuser = False

        form = StaffForm(
            data={
                'company': company.pk,
                'name': 'Hook',
                'description': '',
                'enabled': True,
                'event_type': 'identity.scim.user.provisioned',
                'action_kind': ActionRule.ACTION_WEBHOOK,
                'webhook_url': 'https://example.com/h',
                'webhook_secret': 'secret123',
            },
            instance=None,
        )
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        self.assertNotIn('allow_private_urls', saved.config)

    def test_email_payload_only_valid_for_user_events(self):
        from apps.actions.admin_forms import ActionRuleAdminForm

        company = Company.objects.create(name='Mail', slug='mail-co')

        class StaffForm(ActionRuleAdminForm):
            is_superuser = False

        form = StaffForm(
            data={
                'company': company.pk,
                'name': 'Notify user',
                'description': '',
                'enabled': True,
                'event_type': 'identity.user.created',
                'action_kind': ActionRule.ACTION_EMAIL,
                'email_recipients': '',
                'email_include_payload_email': True,
            },
            instance=None,
        )
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        self.assertTrue(saved.config['include_payload_email'])
        self.assertEqual(saved.config['recipients'], [])

    def test_email_requires_recipient_without_payload_field(self):
        from apps.actions.admin_forms import ActionRuleAdminForm

        company = Company.objects.create(name='Grp', slug='grp-co')

        class StaffForm(ActionRuleAdminForm):
            is_superuser = False

        form = StaffForm(
            data={
                'company': company.pk,
                'name': 'Group mail',
                'description': '',
                'enabled': True,
                'event_type': 'identity.group.created',
                'action_kind': ActionRule.ACTION_EMAIL,
                'email_recipients': '',
                'email_include_payload_email': True,
            },
            instance=None,
        )
        self.assertFalse(form.is_valid())
        self.assertIn('email_recipients', form.errors)


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

    def test_action_outbox_changelist_and_detail_with_attempt_inline(self):
        from django.test import Client

        rule = ActionRule.objects.create(
            company=self.company,
            name='Mail',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['a@test.com']},
        )
        row = ActionOutbox.objects.create(
            company=self.company,
            action_rule=rule,
            event_type='identity.scim.user.provisioned',
            envelope={'id': '1', 'type': 'identity.scim.user.provisioned', 'data': {}},
            status=ActionOutbox.STATUS_DELIVERED,
        )
        DeliveryAttempt.objects.create(
            outbox=row,
            status=DeliveryAttempt.STATUS_SUCCESS,
            attempt_number=1,
            duration_ms=12,
        )
        client = Client()
        client.force_login(self.staff)
        list_url = reverse('admin:actions_actionoutbox_changelist')
        list_response = client.get(list_url)
        self.assertEqual(list_response.status_code, 200)
        self.assertContains(list_response, str(row.pk))
        self.assertContains(list_response, 'identity.scim.user.provisioned')

        detail_url = reverse('admin:actions_actionoutbox_change', args=[row.pk])
        detail_response = client.get(detail_url)
        self.assertEqual(detail_response.status_code, 200)
        self.assertContains(detail_response, 'Delivery attempts')
        self.assertContains(detail_response, 'Envelope JSON')

        attempts_url = reverse('admin:actions_deliveryattempt_changelist')
        self.assertEqual(client.get(attempts_url).status_code, 200)

    def test_action_rule_change_shows_recent_deliveries_inline(self):
        from django.test import Client

        rule = ActionRule.objects.create(
            company=self.company,
            name='Hook rule',
            event_type='identity.group.created',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        ActionOutbox.objects.create(
            company=self.company,
            action_rule=rule,
            event_type='identity.group.created',
            envelope={'id': '2', 'type': 'identity.group.created', 'data': {}},
            status=ActionOutbox.STATUS_PENDING,
        )
        client = Client()
        client.force_login(self.staff)
        url = reverse('admin:actions_actionrule_change', args=[rule.pk])
        response = client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Recent deliveries')
        self.assertContains(response, 'identity.group.created')

    def test_change_form_does_not_echo_webhook_secret(self):
        from django.test import Client

        rule = ActionRule.objects.create(
            company=self.company,
            name='Hook',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 'super-secret-value'},
        )
        client = Client()
        client.force_login(self.staff)
        url = reverse('admin:actions_actionrule_change', args=[rule.pk])
        response = client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'super-secret-value', response.content)

    @patch('apps.actions.admin.messages.success')
    @patch('apps.actions.delivery.deliver_outbox_row')
    def test_retry_admin_action_requeues_without_inline_delivery(self, mock_deliver, _mock_msg):
        from django.contrib.admin.sites import AdminSite
        from django.test import RequestFactory

        from apps.actions.admin import ActionOutboxAdmin

        rule = ActionRule.objects.create(
            company=self.company,
            name='Mail',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['a@test.com']},
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
