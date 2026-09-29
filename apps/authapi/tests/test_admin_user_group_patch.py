from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyGroup

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    AUTH_RATE_LIMIT_ENABLED=False,
)
class AdminUserGroupPatchTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Patch Co', slug='patch-co')
        self.owner = User.objects.create_user(username='owner', email='owner@patch.com', password='x')
        self.target = User.objects.create_user(username='target', email='target@patch.com', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.target, enabled=True)
        self.company.owners.add(self.owner)
        self.manual = CompanyGroup.objects.create(
            company=self.company,
            display_name='Manual',
            source=CompanyGroup.SOURCE_MANUAL,
        )
        self.scim_group = CompanyGroup.create_scim_provisioned(
            company=self.company,
            display_name='From IdP',
        )
        self.client.force_authenticate(user=self.owner)

    def _put_user(self, body):
        return self.client.put(
            f'/api/v1/users/{self.target.pk}?company_id={self.company.pk}',
            body,
            format='json',
        )

    def test_rejects_scim_group_in_group_ids(self):
        response = self._put_user({'group_ids': [self.scim_group.pk]})
        self.assertEqual(response.status_code, 400)
        self.assertIn('SCIM-managed', response.data['error'])

    def test_manual_group_membership_updated(self):
        response = self._put_user({'group_ids': [self.manual.pk]})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.manual.members.filter(pk=self.target.pk).exists())
        self.assertFalse(self.scim_group.members.filter(pk=self.target.pk).exists())
