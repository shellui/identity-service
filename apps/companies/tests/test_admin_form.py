from django.test import TestCase

from apps.companies.access import email_matches_allowed_domains, normalize_allowed_domains
from apps.companies.admin import CompanyAdminForm
from apps.companies.models import Company


class DomainNormalizeTests(TestCase):
    def test_flat_list(self):
        self.assertEqual(
            normalize_allowed_domains(['@Acme.COM', 'acme.com', ' other.io ']),
            ['acme.com', 'other.io'],
        )

    def test_comma_separated_string(self):
        self.assertEqual(
            normalize_allowed_domains('acme.com, other.io'),
            ['acme.com', 'other.io'],
        )

    def test_unwraps_stringified_python_list(self):
        self.assertEqual(
            normalize_allowed_domains(["['sebastienbarbier.com']"]),
            ['sebastienbarbier.com'],
        )

    def test_unwraps_nested_stringified_list(self):
        self.assertEqual(
            normalize_allowed_domains("['sebastienbarbier.com']"),
            ['sebastienbarbier.com'],
        )

    def test_email_match_after_corruption_repair(self):
        self.assertTrue(
            email_matches_allowed_domains(
                'hello@sebastienbarbier.com',
                ["['sebastienbarbier.com']"],
            )
        )


class CompanyAdminFormTests(TestCase):
    def test_parses_comma_separated_domains(self):
        company = Company.objects.create(name='Acme', access_mode=Company.ACCESS_DOMAIN)
        form = CompanyAdminForm(
            data={
                'name': 'Acme',
                'slug': company.slug,
                'access_mode': Company.ACCESS_DOMAIN,
                'allowed_email_domains': '@Acme.COM, other.io',
            },
            instance=company,
        )
        self.assertTrue(form.is_valid(), form.errors)
        obj = form.save()
        self.assertEqual(obj.allowed_email_domains, ['acme.com', 'other.io'])

    def test_widget_does_not_roundtrip_list_repr(self):
        company = Company.objects.create(
            name='Acme',
            access_mode=Company.ACCESS_DOMAIN,
            allowed_email_domains=['sebastienbarbier.com'],
        )
        form = CompanyAdminForm(instance=company)
        prepared = form.fields['allowed_email_domains'].prepare_value(
            company.allowed_email_domains
        )
        self.assertEqual(prepared, 'sebastienbarbier.com')
        self.assertNotIn('[', prepared)

    def test_repairs_corrupted_value_on_save(self):
        company = Company.objects.create(
            name='Acme',
            access_mode=Company.ACCESS_DOMAIN,
            allowed_email_domains=["['sebastienbarbier.com']"],
        )
        form = CompanyAdminForm(
            data={
                'name': 'Acme',
                'slug': company.slug,
                'access_mode': Company.ACCESS_DOMAIN,
                'allowed_email_domains': "['sebastienbarbier.com']",
            },
            instance=company,
        )
        self.assertTrue(form.is_valid(), form.errors)
        obj = form.save()
        self.assertEqual(obj.allowed_email_domains, ['sebastienbarbier.com'])

    def test_domain_mode_requires_domains(self):
        form = CompanyAdminForm(
            data={
                'name': 'Locked',
                'slug': 'locked',
                'access_mode': Company.ACCESS_DOMAIN,
                'allowed_email_domains': '',
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn('allowed_email_domains', form.errors)

    def test_public_mode_allows_empty_domains(self):
        form = CompanyAdminForm(
            data={
                'name': 'Open',
                'slug': 'open',
                'access_mode': Company.ACCESS_PUBLIC,
                'allowed_email_domains': '',
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
