from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from io import StringIO

User = get_user_model()


class ReportDuplicateEmailsCommandTests(TestCase):
    def test_reports_case_insensitive_duplicates(self):
        User.objects.create_user(username='a', email='same@example.com', password='x')
        User.objects.create_user(username='b', email='SAME@example.com', password='x')
        out = StringIO()
        call_command('report_duplicate_emails', stdout=out)
        self.assertIn('same@example.com', out.getvalue())
