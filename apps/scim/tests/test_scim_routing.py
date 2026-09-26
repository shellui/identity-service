from django.test import TestCase

from apps.companies.models import Company
from apps.scim.routing import (
    resolve_company_from_scim_url_segment,
    scim_company_url_segment,
    scim_path_prefix_for_company,
)


class ScimRoutingTests(TestCase):
    def test_canonical_path_uses_primary_key(self):
        company = Company.objects.create(name='Acme', slug='acme')
        self.assertEqual(scim_company_url_segment(company), str(company.pk))
        self.assertEqual(
            scim_path_prefix_for_company(company),
            f'/api/v1/companies/{company.pk}/scim/v2/',
        )

    def test_resolve_by_id(self):
        company = Company.objects.create(name='Acme', slug='acme')
        self.assertEqual(resolve_company_from_scim_url_segment(str(company.pk)), company)

    def test_resolve_by_legacy_slug(self):
        company = Company.objects.create(name='Acme', slug='acme')
        self.assertEqual(resolve_company_from_scim_url_segment('acme'), company)

    def test_numeric_slug_fallback_when_no_pk_match(self):
        company = Company.objects.create(name='Legacy', slug='99999')
        self.assertEqual(resolve_company_from_scim_url_segment('99999'), company)
