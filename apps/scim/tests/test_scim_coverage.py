import json

from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, TestCase, override_settings

from apps.companies.access import is_company_access_enabled, set_company_access
from apps.companies.group_graph import effective_user_ids_for_group
from apps.companies.models import Company, CompanyGroup
from apps.scim.filters import ShellUIGroupFilterQuery, ShellUIUserFilterQuery
from apps.scim.models import CompanyScimToken
from apps.scim.tokens import generate_scim_token

User = get_user_model()

SCIM_ON = {
    'SCIM_ENABLED': True,
    'ALLOWED_HOSTS': ['testserver'],
}


def _scim_base(company: Company) -> str:
    return f'/api/v1/companies/{company.pk}/scim/v2'


@override_settings(**SCIM_ON)
class ScimCoverageTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company = Company.objects.create(name='Acme', slug='acme')
        self.other_company = Company.objects.create(name='Beta', slug='beta')
        raw, prefix, digest = generate_scim_token()
        CompanyScimToken.objects.create(
            company=self.company,
            token_prefix=prefix,
            token_hash=digest,
            name='coverage',
        )
        self.auth_header = f'Bearer {raw}'

    def _post_user(self, email: str) -> User:
        response = self.client.post(
            f'{_scim_base(self.company)}/Users',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
                    'userName': email,
                    'emails': [{'value': email, 'primary': True}],
                    'active': True,
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 201, response.content)
        return User.objects.get(pk=json.loads(response.content)['id'])

    def test_user_delete_deprovisions_one_company_only(self):
        user = self._post_user('dual@acme.com')
        set_company_access(self.other_company, user, enabled=True)

        delete = self.client.delete(
            f'{_scim_base(self.company)}/Users/{user.pk}',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(delete.status_code, 204)
        self.assertTrue(User.objects.filter(pk=user.pk).exists())
        self.assertFalse(is_company_access_enabled(self.company, user))
        self.assertTrue(is_company_access_enabled(self.other_company, user))

    def test_discovery_resource_types_and_service_provider_config(self):
        types_resp = self.client.get(
            f'{_scim_base(self.company)}/ResourceTypes',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(types_resp.status_code, 200)
        type_ids = {r['id'] for r in json.loads(types_resp.content)['Resources']}
        self.assertEqual(type_ids, {'User', 'Group'})

        cfg_resp = self.client.get(
            f'{_scim_base(self.company)}/ServiceProviderConfig',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(cfg_resp.status_code, 200)

    def test_delete_parent_group_keeps_nested_child_group(self):
        user = self._post_user('childuser@acme.com')
        child = CompanyGroup.create_scim_provisioned(company=self.company, display_name='Child')
        child.members.add(user)
        parent = CompanyGroup.create_scim_provisioned(company=self.company, display_name='Parent')
        parent.member_groups.add(child)

        response = self.client.delete(
            f'{_scim_base(self.company)}/Groups/{parent.pk}',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(CompanyGroup.objects.filter(pk=parent.pk).exists())
        self.assertTrue(CompanyGroup.objects.filter(pk=child.pk).exists())
        self.assertTrue(child.members.filter(pk=user.pk).exists())

    def test_patch_remove_user_and_nested_group_members(self):
        user = self._post_user('rm@acme.com')
        child = CompanyGroup.create_scim_provisioned(company=self.company, display_name='RmChild')
        group = CompanyGroup.create_scim_provisioned(company=self.company, display_name='RmParent')
        group.members.add(user)
        group.member_groups.add(child)

        remove_user = self.client.patch(
            f'{_scim_base(self.company)}/Groups/{group.pk}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [
                        {
                            'op': 'remove',
                            'path': 'members',
                            'value': [{'value': str(user.pk), 'type': 'User'}],
                        }
                    ],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(remove_user.status_code, 200, remove_user.content)
        group.refresh_from_db()
        self.assertFalse(group.members.filter(pk=user.pk).exists())
        self.assertTrue(group.member_groups.filter(pk=child.pk).exists())

        remove_child = self.client.patch(
            f'{_scim_base(self.company)}/Groups/{group.pk}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [
                        {
                            'op': 'remove',
                            'path': 'members',
                            'value': [{'value': str(child.pk), 'type': 'Group'}],
                        }
                    ],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(remove_child.status_code, 200, remove_child.content)
        self.assertFalse(group.member_groups.filter(pk=child.pk).exists())

    def test_self_nest_group_via_scim_patch_rejected(self):
        group = CompanyGroup.create_scim_provisioned(company=self.company, display_name='Solo')
        response = self.client.patch(
            f'{_scim_base(self.company)}/Groups/{group.pk}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [
                        {
                            'op': 'add',
                            'path': 'members',
                            'value': [{'value': str(group.pk), 'type': 'Group'}],
                        }
                    ],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(group.member_groups.filter(pk=group.pk).exists())

    def test_deep_nested_effective_users_a_b_c(self):
        user = self._post_user('deep@acme.com')
        c = CompanyGroup.objects.create(company=self.company, display_name='C')
        b = CompanyGroup.objects.create(company=self.company, display_name='B')
        a = CompanyGroup.objects.create(company=self.company, display_name='A')
        c.members.add(user)
        b.member_groups.add(c)
        a.member_groups.add(b)
        self.assertIn(user.pk, effective_user_ids_for_group(a))

    def test_duplicate_display_name_same_company_rejected(self):
        payload = json.dumps(
            {
                'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                'displayName': 'SharedName',
            }
        )
        first = self.client.post(
            f'{_scim_base(self.company)}/Groups',
            data=payload,
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(first.status_code, 201)
        dup = self.client.post(
            f'{_scim_base(self.company)}/Groups',
            data=payload,
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertIn(dup.status_code, {400, 409})

    def test_same_display_name_allowed_in_different_company(self):
        other_token_raw, prefix, digest = generate_scim_token()
        CompanyScimToken.objects.create(
            company=self.other_company,
            token_prefix=prefix,
            token_hash=digest,
            name='beta',
        )
        payload = json.dumps(
            {
                'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                'displayName': 'SharedName',
            }
        )
        self.assertEqual(
            self.client.post(
                f'{_scim_base(self.company)}/Groups',
                data=payload,
                content_type='application/scim+json',
                HTTP_AUTHORIZATION=self.auth_header,
            ).status_code,
            201,
        )
        self.assertEqual(
            self.client.post(
                f'{_scim_base(self.other_company)}/Groups',
                data=payload,
                content_type='application/scim+json',
                HTTP_AUTHORIZATION=f'Bearer {other_token_raw}',
            ).status_code,
            201,
        )

    def test_filter_query_get_extras_include_tenant_sql(self):
        factory = RequestFactory()
        request = factory.get('/')
        request.scim_company = self.company

        user_sql, user_params = ShellUIUserFilterQuery.get_extras(None, request)
        self.assertIn('companies_companymembership', user_sql)
        self.assertEqual(user_params, [self.company.pk])

        group_sql, group_params = ShellUIGroupFilterQuery.get_extras(None, request)
        self.assertIn('company_id', group_sql)
        self.assertIn('source', group_sql)
        self.assertEqual(group_params, [self.company.pk, CompanyGroup.SOURCE_SCIM])

        request.scim_company = None
        blocked_sql, blocked_params = ShellUIUserFilterQuery.get_extras(None, request)
        self.assertIn('1=0', blocked_sql)
        self.assertEqual(blocked_params, [])

    def test_user_get_lists_direct_group_membership(self):
        user = self._post_user('groups@acme.com')
        scim_group = CompanyGroup.create_scim_provisioned(
            company=self.company,
            display_name='Direct',
        )
        scim_group.members.add(user)
        manual_group = CompanyGroup.objects.create(company=self.company, display_name='ManualOnly')
        manual_group.members.add(user)

        response = self.client.get(
            f'{_scim_base(self.company)}/Users/{user.pk}',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 200)
        groups = json.loads(response.content)['groups']
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['value'], str(scim_group.pk))
        self.assertEqual(groups[0]['display'], 'Direct')

    def test_unimplemented_bulk_and_me_return_501_with_auth(self):
        for path in ('Bulk', 'Me'):
            response = self.client.get(
                f'{_scim_base(self.company)}/{path}',
                HTTP_AUTHORIZATION=self.auth_header,
            )
            self.assertEqual(response.status_code, 501, path)
