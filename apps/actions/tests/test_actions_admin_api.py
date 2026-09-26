import uuid

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.emit import emit_event
from apps.actions.handlers.email import deliver_email_action
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

LOC_MEM_EMAIL = {
    'EMAIL_BACKEND': 'django.core.mail.backends.locmem.EmailBackend',
    'ALLOWED_HOSTS': ['testserver', 'localhost', '127.0.0.1'],
    'AUTH_RATE_LIMIT_ENABLED': False,
}


@override_settings(**LOC_MEM_EMAIL)
class ActionsAdminApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Actions Co', slug='actions-co')
        self.other = Company.objects.create(name='Other Actions Co', slug='other-actions-co')
        self.owner = User.objects.create_user(username='owner', email='owner@example.com', password='x')
        self.member = User.objects.create_user(username='member', email='member@example.com', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.member, enabled=True)
        self.company.owners.add(self.owner)
        self.company.members.add(self.owner, self.member)

    def _url(self, path: str, company=None) -> str:
        cid = (company or self.company).id
        sep = '&' if '?' in path else '?'
        return f'{path}{sep}company_id={cid}'

    def _as_owner(self):
        self.client.force_authenticate(user=self.owner)

    def test_events_catalog(self):
        self._as_owner()
        response = self.client.get(self._url('/api/v1/actions/events'))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(len(response.data['results']) >= 5)
        row = next(r for r in response.data['results'] if r['type'] == 'identity.user.created')
        self.assertEqual(row['payload_email_field'], 'email')
        self.assertIn('email', row['supported_action_kinds'])
        self.assertIn('webhook', row['supported_action_kinds'])
        self.assertTrue(any(f['name'] == 'email' for f in row['payload_fields']))
        self.assertEqual(row['email_context_fields'], [])
        self.assertTrue(
            any(f['name'] == 'envelope.company.name' for f in response.data['email_envelope_fields'])
        )

    def test_events_catalog_magic_link_email_context_fields(self):
        self._as_owner()
        response = self.client.get(self._url('/api/v1/actions/events'))
        row = next(
            r for r in response.data['results'] if r['type'] == 'identity.auth.magic_link.requested'
        )
        self.assertTrue(any(f['name'] == 'request_id' for f in row['payload_fields']))
        magic = next(f for f in row['email_context_fields'] if f['name'] == 'magic_link_url')
        self.assertIn('send time', magic['description'].lower())
        self.assertIn('https://', str(magic['example']))
        self.assertNotIn(
            'magic_link_url',
            [f['name'] for f in row['payload_fields']],
        )

    def test_member_forbidden(self):
        self.client.force_authenticate(user=self.member)
        response = self.client.get(self._url('/api/v1/actions/events'))
        self.assertEqual(response.status_code, 403)

    def test_email_rule_crud_and_secret_redaction(self):
        self._as_owner()
        created = self.client.post(
            self._url('/api/v1/actions/rules'),
            {
                'name': 'Ops mail',
                'event_type': 'identity.user.created',
                'action_kind': 'email',
                'recipients': ['ops@actions-co.test'],
                'include_payload_email': False,
            },
            format='json',
        )
        self.assertEqual(created.status_code, 201, created.data)
        rule_id = created.data['id']
        self.assertEqual(created.data['config']['recipients'], ['ops@actions-co.test'])

        listed = self.client.get(self._url('/api/v1/actions/rules'))
        self.assertEqual(listed.data['results'][0]['id'], rule_id)

        patched = self.client.patch(
            self._url(f'/api/v1/actions/rules/{rule_id}'),
            {'enabled': False, 'description': 'paused'},
            format='json',
        )
        self.assertEqual(patched.status_code, 200)
        self.assertFalse(patched.data['enabled'])

        webhook = self.client.post(
            self._url('/api/v1/actions/rules'),
            {
                'name': 'Hook',
                'event_type': 'identity.group.created',
                'action_kind': 'webhook',
                'url': 'https://hooks.example.com/acme',
                'secret': 'whsec_test_secret',
                'authorization_header': 'Bearer static',
            },
            format='json',
        )
        self.assertEqual(webhook.status_code, 201, webhook.data)
        cfg = webhook.data['config']
        self.assertNotIn('secret', cfg)
        self.assertNotIn('authorization_header', cfg)
        self.assertTrue(cfg['secret_set'])
        self.assertTrue(cfg['authorization_header_set'])

        blank_secret = self.client.patch(
            self._url(f'/api/v1/actions/rules/{webhook.data["id"]}'),
            {'secret': '', 'name': 'Hook renamed'},
            format='json',
        )
        self.assertEqual(blank_secret.status_code, 200)
        self.assertTrue(blank_secret.data['config']['secret_set'])

        deleted = self.client.delete(self._url(f'/api/v1/actions/rules/{rule_id}'))
        self.assertEqual(deleted.status_code, 204)

    def test_cross_company_rule_isolation(self):
        self._as_owner()
        other_rule = ActionRule.objects.create(
            company=self.other,
            name='Other',
            event_type='identity.user.created',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['x@y.test']},
        )
        missing = self.client.get(self._url(f'/api/v1/actions/rules/{other_rule.pk}'))
        self.assertEqual(missing.status_code, 404)

    def test_event_default_email_template_en_and_fr(self):
        self._as_owner()
        for lang in ('en', 'fr'):
            response = self.client.get(
                self._url(
                    f'/api/v1/actions/events/identity.user.created/email-template?language={lang}'
                )
            )
            self.assertEqual(response.status_code, 200, response.data)
            self.assertEqual(response.data['source'], 'filesystem')
            self.assertEqual(response.data['language'], lang)
            self.assertIn('{{ data.email', response.data['html'])
            self.assertIn('{{ envelope.company.name }}', response.data['subject'])
            self.assertEqual(response.data['body_html'], response.data['html'])
            self.assertNotIn(self.company.name, response.data['html'])

    def test_event_default_email_template_unknown_event(self):
        self._as_owner()
        response = self.client.get(
            self._url('/api/v1/actions/events/identity.not.a.real.event/email-template?language=en')
        )
        self.assertEqual(response.status_code, 404)

    def test_email_template_effective_and_override_delivery(self):
        self._as_owner()
        created = self.client.post(
            self._url('/api/v1/actions/rules'),
            {
                'name': 'Custom subject',
                'event_type': 'identity.scim.user.provisioned',
                'action_kind': 'email',
                'recipients': ['ops@actions-co.test'],
                'email_templates': {
                    'en': {
                        'subject': 'Custom {{ data.email }}',
                        'html': '<!DOCTYPE html><html><body><p>Override body for {{ data.email }}</p></body></html>',
                    }
                },
            },
            format='json',
        )
        self.assertEqual(created.status_code, 201, created.data)

        template = self.client.get(
            self._url(f'/api/v1/actions/rules/{created.data["id"]}/email-template?language=en')
        )
        self.assertEqual(template.status_code, 200)
        self.assertEqual(template.data['source'], 'override')
        self.assertIn('Custom', template.data['subject'])

        rule = ActionRule.objects.get(pk=created.data['id'])
        envelope = {
            'id': str(uuid.uuid4()),
            'type': 'identity.scim.user.provisioned',
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': self.company.pk, 'slug': self.company.slug, 'name': self.company.name},
            'data': {'email': 'ada@actions-co.test', 'user_id': 1, 'source': 'scim'},
        }
        deliver_email_action(config=rule.config, envelope=envelope)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Custom ada@actions-co.test', mail.outbox[0].subject)
        self.assertIn('Override body', mail.outbox[0].alternatives[0][0])

    def test_delivery_list_filters_and_requeue(self):
        rule = ActionRule.objects.create(
            company=self.company,
            name='Log rule',
            event_type='identity.user.created',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['ops@actions-co.test']},
        )
        with self.captureOnCommitCallbacks(execute=False):
            rows = emit_event(
                'identity.user.created',
                self.company,
                {'user_id': 1, 'email': 'u@actions-co.test', 'source': 'admin'},
            )
        outbox = ActionOutbox.objects.get(pk=rows[0].pk)
        outbox.status = ActionOutbox.STATUS_FAILED
        outbox.last_error = 'smtp down'
        outbox.save(update_fields=['status', 'last_error'])
        DeliveryAttempt.objects.create(
            outbox=outbox,
            status=DeliveryAttempt.STATUS_FAILURE,
            attempt_number=1,
            error_message='smtp down',
        )

        self._as_owner()
        filtered = self.client.get(
            self._url(
                '/api/v1/actions/deliveries'
                f'?status=failed&event_type=identity.user.created&action_rule_id={rule.pk}'
            )
        )
        self.assertEqual(filtered.status_code, 200, filtered.data)
        self.assertEqual(filtered.data['count'], 1)
        self.assertEqual(filtered.data['results'][0]['status'], 'failed')

        detail = self.client.get(self._url(f'/api/v1/actions/deliveries/{outbox.pk}'))
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(len(detail.data['attempts']), 1)
        self.assertIn('envelope', detail.data)

        other_outbox = ActionOutbox.objects.create(
            company=self.other,
            action_rule=ActionRule.objects.create(
                company=self.other,
                name='x',
                event_type='identity.user.created',
                action_kind=ActionRule.ACTION_EMAIL,
                config={'recipients': ['a@b.test']},
            ),
            event_type='identity.user.created',
            envelope={'id': str(uuid.uuid4()), 'type': 'identity.user.created', 'data': {}},
        )
        cross = self.client.get(self._url(f'/api/v1/actions/deliveries/{other_outbox.pk}'))
        self.assertEqual(cross.status_code, 404)

        requeue = self.client.post(self._url(f'/api/v1/actions/deliveries/{outbox.pk}/requeue'))
        self.assertEqual(requeue.status_code, 200)
        self.assertEqual(requeue.data['status'], 'pending')
        self.assertEqual(requeue.data['last_error'], '')

    def test_rejects_script_in_html_override(self):
        self._as_owner()
        bad = self.client.post(
            self._url('/api/v1/actions/rules'),
            {
                'name': 'Bad html',
                'event_type': 'identity.user.created',
                'action_kind': 'email',
                'recipients': ['ops@actions-co.test'],
                'email_templates': {
                    'en': {
                        'subject': 'Hi',
                        'html': '<script>alert(1)</script><p>x</p>',
                    }
                },
            },
            format='json',
        )
        self.assertEqual(bad.status_code, 400)
