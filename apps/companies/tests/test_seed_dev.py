import os
from unittest import mock

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from rest_framework.test import APIClient

from apps.companies.models import Company, CompanyMembership, CompanyOAuthRedirect


class SeedDevGuardTests(TestCase):
    @override_settings(DEBUG=False)
    @mock.patch.dict(os.environ, {'IDENTITY_DEV_SEED': 'true'})
    def test_refuses_when_debug_false(self):
        with self.assertRaises(CommandError):
            call_command('seed_dev')
        self.assertFalse(Company.all_objects.filter(pk=1).exists())
        self.assertFalse(get_user_model().objects.filter(username='admin').exists())

    @override_settings(DEBUG=True)
    @mock.patch.dict(os.environ, {'IDENTITY_DEV_SEED': ''})
    def test_refuses_without_env_flag(self):
        with self.assertRaises(CommandError):
            call_command('seed_dev')
        self.assertFalse(Company.all_objects.filter(pk=1).exists())


@override_settings(DEBUG=True)
@mock.patch.dict(os.environ, {'IDENTITY_DEV_SEED': 'true'})
class SeedDevTests(TestCase):
    def test_seeds_and_is_idempotent(self):
        call_command('seed_dev', stdout=mock.MagicMock())

        company = Company.objects.get(pk=1)
        self.assertEqual(company.name, 'Shellui Dev')
        self.assertTrue(company.enable_magic_link)
        self.assertTrue(
            CompanyOAuthRedirect.objects.filter(company=company, base_url='http://localhost:4000').exists()
        )
        User = get_user_model()
        admin = User.objects.get(username='admin')
        self.assertTrue(admin.is_staff and admin.is_superuser and admin.check_password('admin'))
        dev = User.objects.get(username='dev')
        self.assertEqual(dev.email, 'dev@localhost')
        self.assertFalse(dev.is_staff or dev.is_superuser)
        self.assertTrue(CompanyMembership.objects.filter(company=company, user=dev).exists())

        company.name = 'Renamed'
        company.enable_magic_link = False
        company.save()
        admin.set_password('changed')
        admin.save()

        call_command('seed_dev', stdout=mock.MagicMock())
        company.refresh_from_db()
        admin.refresh_from_db()
        self.assertEqual(company.name, 'Renamed')
        self.assertFalse(company.enable_magic_link)
        self.assertTrue(admin.check_password('changed'))
        self.assertEqual(Company.all_objects.count(), 1)
        self.assertEqual(User.objects.filter(username='admin').count(), 1)
        self.assertEqual(CompanyOAuthRedirect.objects.filter(company=company).count(), 5)

    @override_settings(EMAIL_SERVICE_API_KEY='', EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_dev_user_gets_magic_link_for_shell(self):
        cache.clear()
        call_command('seed_dev', stdout=mock.MagicMock())
        with self.captureOnCommitCallbacks(execute=True):
            response = APIClient().post(
                '/api/v1/magic-link/request',
                {
                    'company_id': 1,
                    'email': 'dev@localhost',
                    'redirect_to': 'http://localhost:4000/',
                    'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                    'code_challenge_method': 'S256',
                },
                format='json',
            )
        self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['dev@localhost'])
