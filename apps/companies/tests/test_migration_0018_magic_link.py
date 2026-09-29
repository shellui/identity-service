import importlib

from django.test import TestCase

from apps.companies.models import Company


class Migration0018MagicLinkDefaultTests(TestCase):
    def test_migration_add_field_default_is_false_for_existing_rows(self):
        migration_0018 = importlib.import_module(
            'apps.companies.migrations.0018_company_enable_magic_link'
        )
        operation = migration_0018.Migration.operations[0]
        self.assertFalse(operation.field.default)

    def test_new_company_model_default_is_true(self):
        company = Company.objects.create(name='Brand new', slug='brand-new-co')
        self.assertTrue(company.enable_magic_link)
