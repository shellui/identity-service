import importlib

from allauth.socialaccount.models import SocialApp
from django.apps import apps
from django.db import migrations
from django.test import TestCase

from apps.companies.models import Company, CompanyOAuthClient

_migration = importlib.import_module(
    'apps.companies.migrations.0034_backfill_social_app_created_by_company'
)


class BackfillSocialAppCreatedByCompanyTests(TestCase):
    def test_backfill_sets_single_mapping_and_leaves_two_companies_untouched(self):
        company_a = Company.objects.create(name='Company A', slug='backfill-a')
        company_b = Company.objects.create(name='Company B', slug='backfill-b')
        single = SocialApp.objects.create(
            provider='github',
            name='single',
            client_id='cid-single',
            secret='secret-single',
            settings={'catalog_slug': 'github'},
        )
        CompanyOAuthClient.objects.create(company=company_a, social_app=single, is_active=True)
        shared = SocialApp.objects.create(
            provider='google',
            name='shared',
            client_id='cid-shared',
            secret='secret-shared',
            settings={'catalog_slug': 'google', 'tenant': 'keep-me'},
        )
        CompanyOAuthClient.objects.bulk_create(
            [
                CompanyOAuthClient(company=company_a, social_app=shared, is_active=True),
                CompanyOAuthClient(company=company_b, social_app=shared, is_active=True),
            ]
        )
        unmapped = SocialApp.objects.create(
            provider='gitlab',
            name='unmapped',
            client_id='cid-unmapped',
            secret='secret-unmapped',
            settings={'catalog_slug': 'gitlab'},
        )
        already = SocialApp.objects.create(
            provider='apple',
            name='already',
            client_id='cid-already',
            secret='secret-already',
            settings={'catalog_slug': 'apple', 'created_by_company_id': company_b.id},
        )
        CompanyOAuthClient.objects.create(company=company_a, social_app=already, is_active=True)

        with self.assertLogs(_migration.logger.name, level='INFO') as logs:
            _migration.backfill_social_app_created_by_company(apps, None)

        single.refresh_from_db()
        shared.refresh_from_db()
        unmapped.refresh_from_db()
        already.refresh_from_db()
        self.assertEqual(single.settings['created_by_company_id'], company_a.id)
        self.assertEqual(single.settings['catalog_slug'], 'github')
        self.assertNotIn('created_by_company_id', shared.settings)
        self.assertEqual(shared.settings['tenant'], 'keep-me')
        self.assertNotIn('created_by_company_id', unmapped.settings)
        self.assertEqual(already.settings['created_by_company_id'], company_b.id)
        self.assertTrue(any('updated=1' in line for line in logs.output))
        self.assertIs(
            _migration.Migration.operations[0].reverse_code,
            migrations.RunPython.noop,
        )
