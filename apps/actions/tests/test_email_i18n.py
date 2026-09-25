from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings

from apps.actions.emit import emit_event
from apps.actions.handlers.email import deliver_email_action
from apps.actions.models import ActionRule
from apps.authapi.models import UserPreference
from apps.companies.models import Company

User = get_user_model()

LOC_MEM_EMAIL = {
    'EMAIL_BACKEND': 'django.core.mail.backends.locmem.EmailBackend',
}


@override_settings(**LOC_MEM_EMAIL)
class ActionEmailI18nTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='I18n Co', slug='i18n-co')
        self.rule = ActionRule.objects.create(
            company=self.company,
            name='Provision mail',
            event_type='identity.scim.user.provisioned',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['ops@i18n.test'], 'include_payload_email': True},
        )

    def test_user_payload_includes_language_and_region(self):
        user = User.objects.create_user(username='ada', email='ada@i18n.test', password='x')
        UserPreference.objects.create(
            user=user,
            language=UserPreference.LANGUAGE_FR,
            region='Europe/Paris',
        )
        from apps.actions.identity_payloads import user_event_payload

        payload = user_event_payload(user, source='scim')
        self.assertEqual(payload['language'], 'fr')
        self.assertEqual(payload['region'], 'Europe/Paris')

    def test_ops_recipients_use_english_by_default(self):
        envelope = {
            'id': 'evt-en',
            'type': 'identity.scim.user.provisioned',
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': self.company.pk, 'slug': 'i18n-co', 'name': 'I18n Co'},
            'data': {
                'user_id': 1,
                'email': 'user@i18n.test',
                'language': 'fr',
                'region': 'Europe/Paris',
                'source': 'scim',
            },
        }
        deliver_email_action(config=self.rule.config, envelope=envelope)
        self.assertEqual(len(mail.outbox), 2)
        ops_msg = mail.outbox[0]
        self.assertEqual(ops_msg.to, ['ops@i18n.test'])
        self.assertIn('SCIM access enabled', ops_msg.alternatives[0][0])

        user_msg = mail.outbox[1]
        self.assertEqual(user_msg.to, ['user@i18n.test'])
        self.assertIn('Accès SCIM activé', user_msg.alternatives[0][0])
        self.assertIn('Accès SCIM activé', user_msg.subject)

    def test_fallback_to_english_when_preferred_template_missing(self):
        envelope = {
            'id': 'evt-de',
            'type': 'identity.scim.user.provisioned',
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': self.company.pk, 'slug': 'i18n-co', 'name': 'I18n Co'},
            'data': {
                'user_id': 2,
                'email': 'de-user@i18n.test',
                'language': 'de',
                'source': 'scim',
            },
        }
        deliver_email_action(
            config={'recipients': [], 'include_payload_email': True},
            envelope=envelope,
        )
        self.assertEqual(len(mail.outbox), 1)
        html = mail.outbox[0].alternatives[0][0]
        self.assertIn('SCIM access enabled', html)

    def test_emit_outbox_envelope_includes_language(self):
        user = User.objects.create_user(username='hook', email='hook@i18n.test', password='x')
        UserPreference.objects.create(user=user, language='fr', region='Europe/Paris')
        from apps.actions.identity_payloads import user_event_payload

        with self.captureOnCommitCallbacks(execute=False):
            rows = emit_event(
                'identity.scim.user.provisioned',
                self.company,
                user_event_payload(user, source='scim'),
            )
        from apps.actions.models import ActionOutbox

        envelope = ActionOutbox.objects.get(pk=rows[0].pk).envelope
        self.assertEqual(envelope['data']['language'], 'fr')
        self.assertEqual(envelope['data']['region'], 'Europe/Paris')
