import json
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings

from apps.actions.email_i18n import MissingCompiledEmailTemplateError, select_rule_email_template
from apps.actions.email_template_defaults import resolve_default_document
from apps.actions.emit import emit_event
from apps.actions.handlers.email import deliver_email_action
from apps.actions.models import ActionRule
from apps.actions.registry import all_event_types
from apps.actions.tests.email_templates import compiled_email_templates, email_rule_config
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
            config=email_rule_config(
                'identity.scim.user.provisioned',
                recipients=['ops@i18n.test'],
                include_payload_email=True,
            ),
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
            config=email_rule_config(
                'identity.scim.user.provisioned', recipients=[], include_payload_email=True
            ),
            envelope=envelope,
        )
        self.assertEqual(len(mail.outbox), 1)
        html = mail.outbox[0].alternatives[0][0]
        self.assertIn('You have access to', html)

    def test_falls_back_to_any_stored_language(self):
        config = {
            'email_templates': compiled_email_templates('identity.user.created', ('fr',)),
        }
        entry, lang = select_rule_email_template(config, preferred='de', use_user_preference=True)
        self.assertEqual(lang, 'fr')
        self.assertIn('Bienvenue chez', entry['html'])

    def test_rule_without_compiled_html_raises(self):
        with self.assertRaises(MissingCompiledEmailTemplateError):
            select_rule_email_template(
                {'recipients': ['ops@i18n.test']}, preferred='en', use_user_preference=False
            )
        with self.assertRaises(MissingCompiledEmailTemplateError):
            deliver_email_action(
                config={'recipients': ['ops@i18n.test']},
                envelope={
                    'id': 'evt-none',
                    'type': 'identity.user.created',
                    'company': {'id': self.company.pk, 'slug': 'i18n-co', 'name': 'I18n Co'},
                    'data': {},
                },
            )
        self.assertEqual(len(mail.outbox), 0)

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

    def test_catalog_events_have_en_fr_json_documents_only(self):
        """Every registered identity event ships a React Email JSON default in en and fr; no HTML."""
        catalog_ids = {event.id for event in all_event_types()}
        base = Path(settings.BASE_DIR) / 'apps/actions/templates/actions/emails'
        self.assertEqual(list(base.rglob('*.html')), [], 'default HTML must not ship on disk')
        for lang in ('en', 'fr'):
            json_events = {p.stem for p in (base / lang).glob('*.json')}
            self.assertEqual(catalog_ids, json_events, f'missing {lang} React Email JSON defaults')
            for event_id in catalog_ids:
                with self.subTest(lang=lang, event=event_id):
                    source = (base / lang / f'{event_id}.json').read_text(encoding='utf-8')
                    self.assertEqual(json.loads(source)['type'], 'doc')
                    self.assertNotIn('{%', source)
                    self.assertNotIn('%}', source)

    def test_french_templates_match_english_set(self):
        base = Path(settings.BASE_DIR) / 'apps/actions/templates/actions/emails'
        en_docs = {p.name for p in (base / 'en').glob('*.json')}
        fr_docs = {p.name for p in (base / 'fr').glob('*.json')}
        self.assertEqual(en_docs, fr_docs)
        en_subjects = {p.name for p in (base / 'en' / 'subjects').glob('*.txt')}
        fr_subjects = {p.name for p in (base / 'fr' / 'subjects').glob('*.txt')}
        self.assertEqual(en_subjects, fr_subjects)

    def test_french_user_created_template_resolves(self):
        event_type = 'identity.user.created'
        document, lang = resolve_default_document(
            event_type,
            preferred='fr',
            use_user_preference=True,
        )
        self.assertEqual(lang, 'fr')
        self.assertEqual(document['type'], 'doc')

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
            config=email_rule_config(event_type, recipients=[], include_payload_email=True),
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
        deliver_email_action(
            config=email_rule_config('identity.scim.user.provisioned', recipients=['ops@i18n.test']),
            envelope=envelope,
        )
        msg = mail.outbox[-1]
        html_part, _mime = msg.alternatives[0]
        self.assertIn('<html', html_part.lower())
        self.assertNotIn('<p', msg.body)
        self.assertIn('You have access to', msg.body)
