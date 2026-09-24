import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone

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


@override_settings(**SCIM_ON)
class ScimDisabledByDefaultTests(TestCase):
    @override_settings(SCIM_ENABLED=False)
    def test_scim_routes_not_mounted_when_disabled(self):
        company = Company.objects.create(name='Off Co', slug='off-co')
        client = Client()
        response = client.get(f'{_scim_base(company)}/ServiceProviderConfig')
        self.assertEqual(response.status_code, 404)


@override_settings(**SCIM_ON)
class ScimApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company = Company.objects.create(name='Acme', slug='acme')
        raw, prefix, digest = generate_scim_token()
        self.scim_token = raw
        CompanyScimToken.objects.create(
            company=self.company,
            token_prefix=prefix,
            token_hash=digest,
            name='okta',
        )
        self.auth_header = f'Bearer {self.scim_token}'

    def test_unauthorized_without_bearer(self):
        response = self.client.get(f'{_scim_base(self.company)}/Users')
        self.assertEqual(response.status_code, 401)

    def test_wrong_company_slug_rejected(self):
        other = Company.objects.create(name='Other', slug='other-co')
        response = self.client.get(
            f'{_scim_base(other)}/Users',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 401)

    def test_create_list_and_patch_user(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'ada@acme.com',
            'name': {'givenName': 'Ada', 'familyName': 'Lovelace'},
            'emails': [{'value': 'ada@acme.com', 'primary': True}],
            'active': True,
        }
        create = self.client.post(
            f'{_scim_base(self.company)}/Users',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(create.status_code, 201, create.content)
        body = json.loads(create.content)
        user_id = body['id']
        user = User.objects.get(scim_attributes__scim_id=user_id)
        self.assertTrue(is_company_access_enabled(self.company, user))

        listing = self.client.get(
            f'{_scim_base(self.company)}/Users',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(listing.status_code, 200)
        listed = json.loads(listing.content)
        self.assertEqual(listed['totalResults'], 1)

        patch = self.client.patch(
            f'{_scim_base(self.company)}/Users/{user_id}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [{'op': 'replace', 'path': 'active', 'value': False}],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(patch.status_code, 200, patch.content)
        self.assertFalse(is_company_access_enabled(self.company, user))

    def test_revoked_token_rejected(self):
        CompanyScimToken.objects.filter(company=self.company).update(revoked_at=timezone.now())
        response = self.client.get(
            f'{_scim_base(self.company)}/Users',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 401)

    def _provision_user(self, email: str) -> User:
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': email,
            'emails': [{'value': email, 'primary': True}],
            'active': True,
        }
        response = self.client.post(
            f'{_scim_base(self.company)}/Users',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 201, response.content)
        user_id = json.loads(response.content)['id']
        return User.objects.get(pk=user_id)

    def test_groups_crud_and_members(self):
        member = self._provision_user('member@acme.com')
        outsider = User.objects.create_user(username='out@other.com', email='out@other.com', password='x')
        other_co = Company.objects.create(name='Other', slug='other2')
        set_company_access(other_co, outsider, enabled=True)

        create = self.client.post(
            f'{_scim_base(self.company)}/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'Engineering',
                    'externalId': 'okta-eng',
                    'members': [{'value': str(member.pk), 'type': 'User'}],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(create.status_code, 201, create.content)
        group_id = json.loads(create.content)['id']
        group = CompanyGroup.objects.get(pk=group_id)
        self.assertEqual(group.display_name, 'Engineering')
        self.assertEqual(group.external_id, 'okta-eng')
        self.assertEqual(group.source, CompanyGroup.SOURCE_SCIM)
        self.assertTrue(group.members.filter(pk=member.pk).exists())

        listing = self.client.get(
            f'{_scim_base(self.company)}/Groups',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(json.loads(listing.content)['totalResults'], 1)

        CompanyGroup.objects.create(company=self.company, display_name='Manual Shell Group')
        listing2 = self.client.get(
            f'{_scim_base(self.company)}/Groups',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(json.loads(listing2.content)['totalResults'], 1)

        bad_member = self.client.post(
            f'{_scim_base(self.company)}/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'Bad',
                    'members': [{'value': str(outsider.pk)}],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(bad_member.status_code, 404)

        patch = self.client.patch(
            f'{_scim_base(self.company)}/Groups/{group_id}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [
                        {
                            'op': 'replace',
                            'path': 'displayName',
                            'value': 'Eng',
                        }
                    ],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(patch.status_code, 200, patch.content)
        group.refresh_from_db()
        self.assertEqual(group.display_name, 'Eng')

        delete = self.client.delete(
            f'{_scim_base(self.company)}/Groups/{group_id}',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(delete.status_code, 204)
        self.assertFalse(CompanyGroup.objects.filter(pk=group_id).exists())
        self.assertTrue(User.objects.filter(pk=member.pk).exists())

    def test_groups_wrong_company_token_rejected(self):
        other = Company.objects.create(name='Other Co', slug='other-co-2')
        response = self.client.get(
            f'{_scim_base(other)}/Groups',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 401)

    def test_nested_groups_and_effective_users(self):
        member = self._provision_user('nested@acme.com')
        child_resp = self.client.post(
            f'{_scim_base(self.company)}/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'ChildTeam',
                    'members': [{'value': str(member.pk), 'type': 'User'}],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(child_resp.status_code, 201, child_resp.content)
        child_id = json.loads(child_resp.content)['id']

        parent_resp = self.client.post(
            f'{_scim_base(self.company)}/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'ParentOrg',
                    'members': [{'value': child_id, 'type': 'Group'}],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(parent_resp.status_code, 201, parent_resp.content)
        parent_id = json.loads(parent_resp.content)['id']

        get_parent = self.client.get(
            f'{_scim_base(self.company)}/Groups/{parent_id}',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(get_parent.status_code, 200)
        members = json.loads(get_parent.content)['members']
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0]['type'], 'Group')
        self.assertEqual(members[0]['value'], child_id)

        parent = CompanyGroup.objects.get(pk=parent_id)
        self.assertIn(member.pk, effective_user_ids_for_group(parent))

    def test_nested_group_cycle_rejected(self):
        a = CompanyGroup.objects.create(
            company=self.company,
            display_name='A',
            source=CompanyGroup.SOURCE_SCIM,
        )
        b = CompanyGroup.objects.create(
            company=self.company,
            display_name='B',
            source=CompanyGroup.SOURCE_SCIM,
        )
        a.member_groups.add(b)
        response = self.client.patch(
            f'{_scim_base(self.company)}/Groups/{b.pk}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [
                        {
                            'op': 'add',
                            'path': 'members',
                            'value': [{'value': str(a.pk), 'type': 'Group'}],
                        }
                    ],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 400)

    def test_nested_cross_company_group_rejected(self):
        other_co = Company.objects.create(name='X', slug='x-co')
        foreign = CompanyGroup.objects.create(company=other_co, display_name='Foreign')
        response = self.client.post(
            f'{_scim_base(self.company)}/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'Local',
                    'members': [{'value': str(foreign.pk), 'type': 'Group'}],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 404)
