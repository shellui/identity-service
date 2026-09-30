from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from apps.authapi.views import _issue_shellui_tokens
from apps.companies.models import Company

User = get_user_model()


class CompanyVerifiedDomainsApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(
            name='Verify Co',
            slug='verify-co',
            verified_email_domains=['platform-set.example'],
        )
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@verify-co.example',
            password='unused',
        )
        self.company.members.add(self.owner)
        self.company.owners.add(self.owner)
        tokens = _issue_shellui_tokens(self.owner, company=self.company)
        self.auth = f'Bearer {tokens["access_token"]}'

    def test_company_owner_cannot_set_verified_email_domains_via_api(self):
        url = f'/api/v1/companies/{self.company.pk}/'
        response = self.client.patch(
            url,
            data={'verified_email_domains': ['attacker-owned.example']},
            format='json',
            HTTP_AUTHORIZATION=self.auth,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.company.refresh_from_db()
        self.assertEqual(self.company.verified_email_domains, ['platform-set.example'])
        self.assertNotIn('verified_email_domains', response.data)
