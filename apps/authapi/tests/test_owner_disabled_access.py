from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    AUTH_RATE_LIMIT_ENABLED=False,
)
class DisabledOwnerForbiddenTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Own Co', slug='own-co')
        self.owner = User.objects.create_user(username='owner', email='owner@own.com', password='x')
        self.company.owners.add(self.owner)
        set_company_access(self.company, self.owner, enabled=False)
        self.client.force_authenticate(user=self.owner)

    def test_deprovisioned_owner_cannot_call_scim_admin(self):
        response = self.client.get(f'/api/v1/scim?company_id={self.company.pk}')
        self.assertEqual(response.status_code, 403)
        self.assertIn('disabled', response.data['error'].lower())
