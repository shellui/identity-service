from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from apps.authapi.views import _issue_shellui_tokens
from apps.companies.models import Company

User = get_user_model()


class CompanyOwnersApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Owners Co', slug='owners-co')
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@owners-co.example',
            password='unused',
        )
        self.member = User.objects.create_user(
            username='member',
            email='member@owners-co.example',
            password='unused',
        )
        self.company.members.add(self.owner, self.member)
        self.company.owners.add(self.owner)
        tokens = _issue_shellui_tokens(self.owner, company=self.company)
        self.auth = f'Bearer {tokens["access_token"]}'
        self.url = f'/api/v1/companies/{self.company.pk}/'

    def test_cannot_remove_every_owner(self):
        response = self.client.patch(
            self.url,
            data={'owner_ids': [], 'name': 'Renamed'},
            format='json',
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error_code'], 'company_owner_required')
        self.company.refresh_from_db()
        self.assertEqual(self.company.name, 'Owners Co')
        self.assertEqual(list(self.company.owners.values_list('pk', flat=True)), [self.owner.pk])

    def test_can_hand_ownership_to_another_member(self):
        response = self.client.patch(
            self.url,
            data={'owner_ids': [self.member.pk]},
            format='json',
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(list(self.company.owners.values_list('pk', flat=True)), [self.member.pk])
