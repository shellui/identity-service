"""Company deletion: flag, hide, refuse tokens, purge, propagate, notify the dashboard."""

from __future__ import annotations

import json
from unittest import mock

import jwt
from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.settings import api_settings

from apps.authapi import views as auth_views
from apps.companies import deletion
from apps.companies.admin import CompanyAdmin
from apps.companies.models import Company, CompanyDeletionNotice
from apps.federation.models import ProvisionedCompany

User = get_user_model()
STORAGE = 'https://storage.eu.example'
HOSTING = 'https://hosting.eu.example'


def _response(status):
    return mock.Mock(status_code=status)


class CompanyDeletionTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme')
        self.user = User.objects.create_user(username='a', email='a@example.com', password='x')
        self.company.members.add(self.user)

    def test_flag_hides_company_and_keeps_data(self):
        deletion.request_company_deletion(self.company)
        deletion.request_company_deletion(self.company)
        self.assertFalse(Company.objects.filter(pk=self.company.pk).exists())
        self.assertFalse(self.user.companies.exists())
        self.assertTrue(Company.all_objects.filter(pk=self.company.pk).exists())

    def test_flag_marks_provisioned_row(self):
        ProvisionedCompany.objects.create(company=self.company, global_company_id='g-1')
        deletion.request_company_deletion(self.company)
        row = ProvisionedCompany.objects.get(company_id=self.company.pk)
        self.assertEqual(row.status, ProvisionedCompany.STATUS_DELETING)
        self.assertIsNotNone(row.deletion_requested_at)

    def test_tokens_refused_for_deleting_company(self):
        deletion.request_company_deletion(self.company)
        with self.assertRaises(PermissionDenied):
            auth_views._issue_tokens(self.user, self.company)

    def test_admin_delete_only_flags(self):
        admin = CompanyAdmin(Company, AdminSite())
        request = RequestFactory().post('/')
        admin.delete_model(request, self.company)
        self.assertTrue(Company.all_objects.filter(pk=self.company.pk).exists())
        self.assertTrue(deletion.is_company_deleting(self.company))

    def test_admin_bulk_delete_only_flags(self):
        other = Company.objects.create(name='Other')
        admin = CompanyAdmin(Company, AdminSite())
        admin.delete_queryset(RequestFactory().post('/'), Company.objects.filter(pk__in=[self.company.pk, other.pk]))
        self.assertEqual(Company.all_objects.filter(deletion_requested_at__isnull=False).count(), 2)
        self.assertEqual(Company.objects.count(), 0)

    @override_settings(
        STORAGE_SERVICE_URL=STORAGE,
        HOSTING_SERVICE_URL='',
        EMAIL_SERVICE_URL='https://email.eu.example',
        EMAIL_SERVICE_API_KEY='esk_test',  # gitleaks:allow
    )
    def test_unset_service_is_skipped_with_a_warning(self):
        deletion.request_company_deletion(self.company)
        with mock.patch.object(deletion.requests, 'post', return_value=_response(202)) as post:
            with self.assertLogs('apps.companies.deletion', 'WARNING') as logs:
                self.assertEqual(deletion.purge_deleted_companies()['purged'], 1)
        called = [c.args[0] for c in post.call_args_list]
        self.assertEqual(
            called,
            [f'{STORAGE}{deletion.DELETION_PATH}', f'https://email.eu.example{deletion.DELETION_PATH}'],
        )
        self.assertIn('HOSTING_SERVICE_URL', ''.join(logs.output))
        self.assertNotIn('esk_test', ''.join(logs.output))

    @override_settings(EMAIL_SERVICE_API_KEY='')
    def test_email_skipped_without_email_service_key(self):
        self.assertNotIn('EMAIL_SERVICE_URL', [n for n, u in deletion.deletion_services() if u])

    def test_purge_without_services_deletes_immediately(self):
        deletion.request_company_deletion(self.company)
        stats = deletion.purge_deleted_companies()
        self.assertEqual(stats['purged'], 1)
        self.assertFalse(Company.all_objects.filter(pk=self.company.pk).exists())
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    @override_settings(STORAGE_SERVICE_URL=STORAGE, HOSTING_SERVICE_URL=HOSTING + '/')
    def test_purge_waits_for_every_service_and_retries(self):
        deletion.request_company_deletion(self.company)
        with mock.patch.object(deletion.requests, 'post', side_effect=[_response(202), _response(503)]) as post:
            self.assertEqual(deletion.purge_deleted_companies()['pending'], 1)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(Company.all_objects.get(pk=self.company.pk).deletion_acks, [STORAGE])
        with mock.patch.object(deletion.requests, 'post', return_value=_response(202)) as post:
            self.assertEqual(deletion.purge_deleted_companies()['purged'], 1)
        # Only the service that had not answered is asked again.
        self.assertEqual(post.call_args.args[0], f'{HOSTING}/api/v1/internal/company-deletions')
        self.assertFalse(Company.all_objects.filter(pk=self.company.pk).exists())

    @override_settings(STORAGE_SERVICE_URL=STORAGE, HOSTING_SERVICE_URL='')
    def test_error_body_snippet_is_logged(self):
        deletion.request_company_deletion(self.company)
        bad = mock.Mock(status_code=400, text='<h1>Bad Request (400)</h1>')
        with mock.patch.object(deletion.requests, 'post', return_value=bad):
            with self.assertLogs('apps.companies.deletion', level='WARNING') as logs:
                deletion.purge_deleted_companies()
        self.assertTrue(any('Bad Request (400)' in line and 'ALLOWED_HOSTS' in line for line in logs.output))

    @override_settings(STORAGE_SERVICE_URL=STORAGE, HOSTING_SERVICE_URL=HOSTING)
    def test_redirect_is_not_followed_and_is_logged(self):
        deletion.request_company_deletion(self.company)
        redirect = mock.Mock(status_code=301, headers={'Location': 'https://storage.eu.example/api/v1/internal/company-deletions'})
        with mock.patch.object(deletion.requests, 'post', side_effect=[redirect, _response(202)]) as post:
            with self.assertLogs('apps.companies.deletion', level='WARNING') as logs:
                self.assertEqual(deletion.purge_deleted_companies()['pending'], 1)
        self.assertFalse(post.call_args_list[0].kwargs['allow_redirects'])
        self.assertTrue(any('redirected (301' in line for line in logs.output))
        self.assertTrue(Company.all_objects.filter(pk=self.company.pk).exists())

    def test_assertion_is_not_a_user_token(self):
        token = deletion.build_deletion_assertion(self.company.pk, STORAGE)
        claims = jwt.decode(
            token,
            api_settings.VERIFYING_KEY or api_settings.SIGNING_KEY,
            algorithms=[api_settings.ALGORITHM],
            audience=deletion.DELETION_AUDIENCE,
        )
        self.assertEqual(claims['company_id'], self.company.pk)
        self.assertEqual(claims['scope'], 'company.delete')
        self.assertLessEqual(claims['exp'] - claims['iat'], 60)
        with self.assertRaises(jwt.InvalidAudienceError):
            jwt.decode(
                token,
                api_settings.VERIFYING_KEY or api_settings.SIGNING_KEY,
                algorithms=[api_settings.ALGORITHM],
                audience=api_settings.AUDIENCE or 'shellui',
            )

    @override_settings(DASHBOARD_WEBHOOK_URL='https://dashboard.example/api/v1/webhooks/eu', DASHBOARD_WEBHOOK_SECRET='whsec_c2VjcmV0c2VjcmV0c2VjcmV0')
    def test_dashboard_notice_sent_after_purge(self):
        ProvisionedCompany.objects.create(company=self.company, global_company_id='g-1')
        deletion.request_company_deletion(self.company)
        with mock.patch.object(deletion.requests, 'post', return_value=_response(200)) as post:
            stats = deletion.purge_deleted_companies()
        self.assertEqual(stats['notices_sent'], 1)
        body = json.loads(post.call_args.kwargs['data'])
        self.assertEqual(body['type'], 'identity.company.deleted')
        self.assertEqual(body['data']['global_company_id'], 'g-1')
        self.assertIn('webhook-signature', post.call_args.kwargs['headers'])
        self.assertFalse(CompanyDeletionNotice.objects.exists())

    @override_settings(DASHBOARD_WEBHOOK_URL='https://dashboard.example/api/v1/webhooks/eu', DASHBOARD_WEBHOOK_SECRET='s')
    def test_dashboard_notice_retried_on_failure(self):
        ProvisionedCompany.objects.create(company=self.company, global_company_id='g-2')
        deletion.request_company_deletion(self.company)
        with mock.patch.object(deletion.requests, 'post', return_value=_response(500)):
            deletion.purge_deleted_companies()
        self.assertEqual(CompanyDeletionNotice.objects.get().attempts, 1)
        with mock.patch.object(deletion.requests, 'post', return_value=_response(200)):
            deletion.purge_deleted_companies()
        self.assertFalse(CompanyDeletionNotice.objects.exists())
