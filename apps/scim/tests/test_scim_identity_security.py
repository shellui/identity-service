import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from apps.companies.access import is_company_access_enabled, set_company_access
from apps.companies.models import Company
from apps.scim.tests.test_scim_tenant_isolation import SCIM_ON, _scim_base, _token_for

User = get_user_model()

_SCIM_ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error'


@override_settings(**SCIM_ON)
class ScimIdentitySecurityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company_a = Company.objects.create(name='Company A', slug='company-a-scim-sec')
        self.company_b = Company.objects.create(name='Company B', slug='company-b-scim-sec')
        self.token_a = _token_for(self.company_a)
        self.auth_a = f'Bearer {self.token_a}'

        self.victim = User.objects.create_user(
            username='victim@example.com',
            email='victim@example.com',
            password='before-scim',
        )
        set_company_access(self.company_b, self.victim, enabled=True)
        set_company_access(self.company_a, self.victim, enabled=False)

        self.staff = User.objects.create_user(
            username='staff@example.com',
            email='staff@example.com',
            password='staff-pass',
            is_staff=True,
        )
        set_company_access(self.company_a, self.staff, enabled=True)

    def _put_user(self, user_pk, payload):
        return self.client.put(
            f'{_scim_base(self.company_a)}/Users/{user_pk}',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_a,
        )

    def test_cannot_change_email_for_cross_company_user(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'attacker@evil.test',
            'emails': [{'value': 'attacker@evil.test', 'primary': True}],
            'active': True,
        }
        response = self._put_user(self.victim.pk, payload)
        self.assertEqual(response.status_code, 409)
        body = json.loads(response.content)
        self.assertIn(_SCIM_ERROR, body['schemas'])
        self.victim.refresh_from_db()
        self.assertEqual(self.victim.email, 'victim@example.com')

    def test_cannot_set_password_for_cross_company_user(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'victim@example.com',
            'emails': [{'value': 'victim@example.com', 'primary': True}],
            'password': 'hacked-password',
            'active': True,
        }
        response = self._put_user(self.victim.pk, payload)
        self.assertEqual(response.status_code, 400)
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.check_password('before-scim'))

    def test_cannot_change_staff_user_email(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'staff@example.com',
            'emails': [{'value': 'newstaff@evil.test', 'primary': True}],
            'active': True,
        }
        response = self._put_user(self.staff.pk, payload)
        self.assertEqual(response.status_code, 409)
        self.staff.refresh_from_db()
        self.assertEqual(self.staff.email, 'staff@example.com')

    def test_password_in_body_rejected(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'solo@acme.test',
            'emails': [{'value': 'solo@acme.test', 'primary': True}],
            'password': 'nope',
            'active': True,
        }
        response = self.client.post(
            f'{_scim_base(self.company_a)}/Users',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 400)

    def test_duplicate_email_post_returns_409_not_second_user(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'other-name',
            'emails': [{'value': 'victim@example.com', 'primary': True}],
            'active': True,
        }
        response = self.client.post(
            f'{_scim_base(self.company_a)}/Users',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(User.objects.filter(email__iexact='victim@example.com').count(), 1)

    def test_single_company_provision_still_works(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'solo@acme.test',
            'name': {'givenName': 'Solo', 'familyName': 'User'},
            'emails': [{'value': 'solo@acme.test', 'primary': True}],
            'active': True,
        }
        response = self.client.post(
            f'{_scim_base(self.company_a)}/Users',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 201, response.content)
        user = User.objects.get(email='solo@acme.test')
        self.assertTrue(is_company_access_enabled(self.company_a, user))
        self.assertEqual(user.company_memberships.count(), 1)
