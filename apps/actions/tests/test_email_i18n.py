from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings

from django.template.loader import get_template

from apps.actions.email_i18n import resolve_body_template, resolve_subject_template_name
from apps.actions.emit import emit_event
from apps.actions.handlers.email import deliver_email_action
from apps.actions.registry import all_event_types
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
        self.assertIn('You have access to', ops_msg.alternatives[0][0])

        user_msg = mail.outbox[1]
        self.assertEqual(user_msg.to, ['user@i18n.test'])
        self.assertIn('Vous avez accès', user_msg.alternatives[0][0])
        self.assertIn('Vous avez accès', user_msg.subject)

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
        self.assertIn('You have access to', html)

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

    def test_catalog_events_have_en_fr_html_bodies(self):
        """Every registered identity event ships full HTML bodies in en and fr."""
        catalog_ids = {event.id for event in all_event_types()}
        base = Path(settings.BASE_DIR) / 'apps/actions/templates/actions/emails'
        for lang in ('en', 'fr'):
            html_events = {p.stem for p in (base / lang).glob('*.html')}
            self.assertEqual(
                catalog_ids,
                html_events,
                f'missing or extra {lang} HTML templates vs event catalog',
            )
            for event_id in catalog_ids:
                template_name = f'actions/emails/{lang}/{event_id}.html'
                with self.subTest(lang=lang, event=event_id):
                    get_template(template_name)

    def test_french_templates_match_english_set(self):
        base = Path(settings.BASE_DIR) / 'apps/actions/templates/actions/emails'
        en_html = {p.name for p in (base / 'en').glob('*.html')}
        fr_html = {p.name for p in (base / 'fr').glob('*.html')}
        self.assertEqual(en_html, fr_html)
        en_subjects = {p.name for p in (base / 'en' / 'subjects').glob('*.txt')}
        fr_subjects = {p.name for p in (base / 'fr' / 'subjects').glob('*.txt')}
        self.assertEqual(en_subjects, fr_subjects)

    def test_french_user_created_template_resolves(self):
        event_type = 'identity.user.created'
        body_name, lang = resolve_body_template(
            event_type,
            preferred='fr',
            use_user_preference=True,
        )
        self.assertEqual(lang, 'fr')
        self.assertEqual(body_name, 'actions/emails/fr/identity.user.created.html')
        subject_name, subject_lang = resolve_subject_template_name(
            event_type,
            preferred='fr',
            use_user_preference=True,
        )
        self.assertEqual(subject_lang, 'fr')
        self.assertEqual(subject_name, 'actions/emails/fr/subjects/identity.user.created.txt')

        envelope = {
            'id': 'evt-fr-created',
            'type': event_type,
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': self.company.pk, 'slug': 'i18n-co', 'name': 'I18n Co'},
            'data': {
                'user_id': 3,
                'email': 'new@i18n.test',
                'language': 'fr',
                'source': 'oauth',
            },
        }
        deliver_email_action(
            config={'recipients': [], 'include_payload_email': True},
            envelope=envelope,
        )
        msg = mail.outbox[-1]
        html_part, mime = msg.alternatives[0]
        self.assertEqual(mime, 'text/html')
        self.assertIn('Bienvenue chez', html_part)
        self.assertIn('Bienvenue chez', msg.subject)
        self.assertNotIn('<h1', msg.body)
        self.assertIn('Bienvenue chez', msg.body)

    def test_plain_text_part_derived_from_html_via_html2text(self):
        envelope = {
            'id': 'evt-plain',
            'type': 'identity.scim.user.provisioned',
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': self.company.pk, 'slug': 'i18n-co', 'name': 'I18n Co'},
            'data': {'user_id': 1, 'email': 'plain@i18n.test', 'source': 'scim'},
        }
        deliver_email_action(config={'recipients': ['ops@i18n.test']}, envelope=envelope)
        msg = mail.outbox[-1]
        html_part, _mime = msg.alternatives[0]
        self.assertIn('<html', html_part.lower())
        self.assertNotIn('<p', msg.body)
        self.assertIn('You have access to', msg.body)
