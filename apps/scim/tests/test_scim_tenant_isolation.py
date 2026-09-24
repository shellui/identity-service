import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from apps.companies.access import is_company_access_enabled, set_company_access
from apps.companies.group_graph import effective_user_ids_for_group
from apps.companies.models import Company, CompanyGroup
from apps.scim.models import CompanyScimToken
from apps.scim.tokens import generate_scim_token

User = get_user_model()

SCIM_ON = {
    'SCIM_ENABLED': True,
    'ALLOWED_HOSTS': ['testserver'],
}


def _scim_base(company: Company) -> str:
    return f'/api/v1/companies/{company.slug}/scim/v2'


def _token_for(company: Company) -> str:
    raw, prefix, digest = generate_scim_token()
    CompanyScimToken.objects.create(
        company=company,
        token_prefix=prefix,
        token_hash=digest,
        name='test',
    )
    return raw


@override_settings(**SCIM_ON)
class ScimTenantIsolationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company_a = Company.objects.create(name='Company A', slug='company-a')
        self.company_b = Company.objects.create(name='Company B', slug='company-b')
        self.token_a = _token_for(self.company_a)
        self.auth_a = f'Bearer {self.token_a}'

        self.user_b_only = User.objects.create_user(username='bonly', email='bonly@b.com', password='x')
        set_company_access(self.company_b, self.user_b_only, enabled=True)

        self.user_both = User.objects.create_user(username='both', email='both@example.com', password='x')
        set_company_access(self.company_a, self.user_both, enabled=True)
        set_company_access(self.company_b, self.user_both, enabled=True)

        self.group_b = CompanyGroup.create_scim_provisioned(
            company=self.company_b,
            display_name='B Group',
        )
        self.group_a = CompanyGroup.create_scim_provisioned(
            company=self.company_a,
            display_name='A Group',
        )

    def test_token_slug_mismatch_is_401(self):
        response = self.client.get(
            f'{_scim_base(self.company_b)}/Users',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 401)

    def test_get_user_from_other_company_is_404(self):
        response = self.client.get(
            f'{_scim_base(self.company_a)}/Users/{self.user_b_only.pk}',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 404)

    def test_list_users_excludes_other_company_only_members(self):
        response = self.client.get(
            f'{_scim_base(self.company_a)}/Users',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 200)
        ids = {r['id'] for r in json.loads(response.content)['Resources']}
        self.assertIn(str(self.user_both.pk), ids)
        self.assertNotIn(str(self.user_b_only.pk), ids)

    def test_get_group_from_other_company_is_404(self):
        response = self.client.get(
            f'{_scim_base(self.company_a)}/Groups/{self.group_b.pk}',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 404)

    def test_cannot_add_other_company_user_to_group(self):
        response = self.client.patch(
            f'{_scim_base(self.company_a)}/Groups/{self.group_a.pk}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [
                        {
                            'op': 'add',
                            'path': 'members',
                            'value': [{'value': str(self.user_b_only.pk), 'type': 'User'}],
                        }
                    ],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 404)
        self.assertFalse(self.group_a.members.filter(pk=self.user_b_only.pk).exists())

    def test_cannot_add_other_company_nested_group(self):
        response = self.client.patch(
            f'{_scim_base(self.company_a)}/Groups/{self.group_a.pk}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [
                        {
                            'op': 'add',
                            'path': 'members',
                            'value': [{'value': str(self.group_b.pk), 'type': 'Group'}],
                        }
                    ],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 404)
        self.assertFalse(self.group_a.member_groups.filter(pk=self.group_b.pk).exists())

    def test_user_groups_in_payload_are_company_a_only(self):
        self.group_a.members.add(self.user_both)
        self.group_b.members.add(self.user_both)
        response = self.client.get(
            f'{_scim_base(self.company_a)}/Users/{self.user_both.pk}',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 200)
        groups = json.loads(response.content)['groups']
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['value'], str(self.group_a.pk))

    def test_deprovision_on_a_leaves_b_membership(self):
        response = self.client.patch(
            f'{_scim_base(self.company_a)}/Users/{self.user_both.pk}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [{'op': 'replace', 'path': 'active', 'value': False}],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(is_company_access_enabled(self.company_a, self.user_both))
        self.assertTrue(is_company_access_enabled(self.company_b, self.user_both))
        self.assertTrue(User.objects.filter(pk=self.user_both.pk).exists())

    def test_effective_membership_does_not_cross_companies(self):
        child_b = CompanyGroup.objects.create(company=self.company_b, display_name='Child B')
        child_b.members.add(self.user_b_only)
        self.group_a.member_groups.add(child_b)
        effective = effective_user_ids_for_group(self.group_a)
        self.assertNotIn(self.user_b_only.pk, effective)
