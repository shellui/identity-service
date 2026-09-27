from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.email_test_send import send_action_email_test_to_self
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

LOC_MEM_EMAIL = {
    'EMAIL_BACKEND': 'django.core.mail.backends.locmem.EmailBackend',
    'ALLOWED_HOSTS': ['testserver', 'localhost', '127.0.0.1'],
    'AUTH_RATE_LIMIT_ENABLED': False,
}


@override_settings(**LOC_MEM_EMAIL)
class EmailTestSendHelperTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Send Co', slug='send-co')

    def test_sends_only_to_provided_address_with_sample_substitution(self):
        result = send_action_email_test_to_self(
            user_email='owner@example.com',
            event_type='identity.user.created',
            company=self.company,
            language='en',
            subject='Hello {{ envelope.company.name }}',
            html='<p>Hi {{ data.email }}</p>',
        )
        self.assertEqual(result['sent_to'], 'owner@example.com')
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ['owner@example.com'])
        self.assertTrue(msg.subject.startswith('[Test]'))
        self.assertIn('Send Co', msg.subject)
        self.assertIn('Hi ', msg.alternatives[0][0])
        self.assertNotIn('{{', msg.alternatives[0][0])

    def test_rejects_empty_html_and_email(self):
        with self.assertRaises(ValueError):
            send_action_email_test_to_self(
                user_email='',
                event_type='identity.user.created',
                company=self.company,
                language='en',
                subject='x',
                html='<p>y</p>',
            )
        with self.assertRaises(ValueError):
            send_action_email_test_to_self(
                user_email='a@b.com',
                event_type='identity.user.created',
                company=self.company,
                language='en',
                subject='x',
                html='  ',
            )


@override_settings(**LOC_MEM_EMAIL)
class EmailTestSendApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='API Co', slug='api-co')
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@api.co',
            password='pass',
        )
        self.member = User.objects.create_user(
            username='member',
            email='member@api.co',
            password='pass',
        )
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.member, enabled=True)
        self.company.owners.add(self.owner)
        self.company.members.add(self.owner, self.member)

    def _url(self, path: str) -> str:
        sep = '&' if '?' in path else '?'
        return f'{path}{sep}company_id={self.company.pk}'

    def test_owner_can_send_test_to_self(self):
        self.client.force_authenticate(user=self.owner)
        response = self.client.post(
            self._url('/api/v1/actions/events/identity.user.created/email-template/send-test'),
            {
                'language': 'en',
                'subject': 'Welcome {{ envelope.company.name }}',
                'html': '<p>{{ data.email }}</p>',
            },
            format='json',
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['sent_to'], 'owner@api.co')
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['owner@api.co'])

    def test_member_forbidden(self):
        self.client.force_authenticate(user=self.member)
        response = self.client.post(
            self._url('/api/v1/actions/events/identity.user.created/email-template/send-test'),
            {'html': '<p>x</p>', 'subject': 's'},
            format='json',
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(mail.outbox), 0)

    def test_unknown_event_404(self):
        self.client.force_authenticate(user=self.owner)
        response = self.client.post(
            self._url('/api/v1/actions/events/identity.not.real/email-template/send-test'),
            {'html': '<p>x</p>'},
            format='json',
        )
        self.assertEqual(response.status_code, 404)
