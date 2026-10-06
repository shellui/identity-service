import io

from django.core.mail import EmailMultiAlternatives
from django.test import SimpleTestCase

from config.email_backends import ConsoleEmailBackend


class ConsoleEmailBackendTests(SimpleTestCase):
    def test_prints_decoded_body_with_usable_urls(self):
        url = (
            'http://localhost:8000/api/v1/magic-link/verify'
            '?token=AsKIRDVhPj8pwbLgWjIpTjnuKJaLIGk0X1phCNDH9ec&company_id=1'
        )
        message = EmailMultiAlternatives(
            subject='Sign in',
            body=f'Shellui · Acme\n\nSign in with this one-time link:\n{url}\n',
            from_email='noreply@localhost',
            to=['ada@acme.com'],
        )
        message.attach_alternative(f'<a href="{url}">Sign in</a>', 'text/html')
        stream = io.StringIO()

        sent = ConsoleEmailBackend(stream=stream).send_messages([message])

        self.assertEqual(sent, 1)
        output = stream.getvalue()
        self.assertIn(url, output)
        self.assertIn('Shellui · Acme', output)
        self.assertIn('To: ada@acme.com', output)
        self.assertIn('Alternatives: text/html', output)
        self.assertNotIn('=3D', output)
