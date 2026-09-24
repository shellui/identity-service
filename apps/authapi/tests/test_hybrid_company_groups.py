import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.tokens import ShellUIAccessToken
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyGroup
from apps.scim.models import CompanyScimToken, ScimProvisioningEvent
from apps.scim.tokens import generate_scim_token

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    SCIM_ENABLED=True,
    OAUTH_TOKEN_DELIVERY='code',
)
class HybridCompanyGroupTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.scim_client = Client()
        self.company = Company.objects.create(name='Hybrid Co', slug='hybrid-co')
        self.owner = User.objects.create_user(username='owner', email='owner@hybrid.com', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.user = User.objects.create_user(username='member', email='member@hybrid.com', password='x')
        set_company_access(self.company, self.user, enabled=True)

        raw, prefix, digest = generate_scim_token()
        self.scim_token = raw
        CompanyScimToken.objects.create(
            company=self.company,
            token_prefix=prefix,
            token_hash=digest,
            name='idp',
        )

    def _admin_url(self, path: str) -> str:
        return f'{path}?company_id={self.company.id}'

    def _as_owner(self):
        self.client.force_authenticate(user=self.owner)

    def test_existing_groups_default_to_manual_source(self):
        legacy = CompanyGroup.objects.create(company=self.company, display_name='Legacy')
        self.assertEqual(legacy.source, CompanyGroup.SOURCE_MANUAL)

    def test_admin_can_create_manual_group_while_scim_configured(self):
        self._as_owner()
        response = self.client.post(
            self._admin_url('/api/v1/groups'),
            {'display_name': 'Shell Team'},
            format='json',
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['source'], CompanyGroup.SOURCE_MANUAL)

    def test_admin_cannot_mutate_scim_sourced_group(self):
        create = self.scim_client.post(
            f'/api/v1/companies/{self.company.slug}/scim/v2/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'IdP Group',
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=f'Bearer {self.scim_token}',
        )
        self.assertEqual(create.status_code, 201, create.content)
        group_id = json.loads(create.content)['id']

        self._as_owner()
        blocked_put = self.client.put(
            self._admin_url(f'/api/v1/groups/{group_id}'),
            {'display_name': 'Renamed'},
            format='json',
        )
        self.assertEqual(blocked_put.status_code, 403, blocked_put.data)

        blocked_delete = self.client.delete(self._admin_url(f'/api/v1/groups/{group_id}'))
        self.assertEqual(blocked_delete.status_code, 403)

    def test_jwt_lists_manual_and_scim_effective_groups(self):
        manual = CompanyGroup.objects.create(company=self.company, display_name='ManualLeaf')
        manual.members.add(self.user)
        scim_child = CompanyGroup.create_scim_provisioned(
            company=self.company,
            display_name='ScimChild',
        )
        scim_parent = CompanyGroup.create_scim_provisioned(
            company=self.company,
            display_name='ScimParent',
        )
        scim_child.members.add(self.user)
        scim_parent.member_groups.add(scim_child)

        tokens = _issue_shellui_tokens(self.user, company=self.company)
        access = ShellUIAccessToken(tokens['access_token'])
        self.assertEqual(
            sorted(access['user_metadata']['groups']),
            sorted(['ManualLeaf', 'ScimChild', 'ScimParent']),
        )

    def test_admin_create_conflicts_with_scim_display_name(self):
        create = self.scim_client.post(
            f'/api/v1/companies/{self.company.slug}/scim/v2/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'Shared Name',
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=f'Bearer {self.scim_token}',
        )
        self.assertEqual(create.status_code, 201, create.content)

        self._as_owner()
        response = self.client.post(
            self._admin_url('/api/v1/groups'),
            {'display_name': 'Shared Name'},
            format='json',
        )
        self.assertEqual(response.status_code, 409, response.data)
        self.assertIn('SCIM', response.data['error'])
        self.assertEqual(
            CompanyGroup.objects.filter(company=self.company, display_name='Shared Name').count(),
            1,
        )

    def test_scim_create_conflicts_with_manual_display_name(self):
        manual = CompanyGroup.objects.create(company=self.company, display_name='Shell Only')
        response = self.scim_client.post(
            f'/api/v1/companies/{self.company.slug}/scim/v2/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'Shell Only',
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=f'Bearer {self.scim_token}',
        )
        self.assertEqual(response.status_code, 409, response.content)
        body = json.loads(response.content)
        self.assertIn('manual', body['detail'].lower())
        manual.refresh_from_db()
        self.assertEqual(manual.source, CompanyGroup.SOURCE_MANUAL)
        self.assertFalse(
            CompanyGroup.objects.filter(
                company=self.company,
                display_name='Shell Only',
                source=CompanyGroup.SOURCE_SCIM,
            ).exists()
        )

    def test_scim_rename_conflicts_with_manual_display_name(self):
        CompanyGroup.objects.create(company=self.company, display_name='Taken Manual')
        create = self.scim_client.post(
            f'/api/v1/companies/{self.company.slug}/scim/v2/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'IdP Rename Me',
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=f'Bearer {self.scim_token}',
        )
        self.assertEqual(create.status_code, 201, create.content)
        group_id = json.loads(create.content)['id']

        patch = self.scim_client.patch(
            f'/api/v1/companies/{self.company.slug}/scim/v2/Groups/{group_id}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [
                        {'op': 'replace', 'path': 'displayName', 'value': 'Taken Manual'},
                    ],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=f'Bearer {self.scim_token}',
        )
        self.assertEqual(patch.status_code, 409, patch.content)
        group = CompanyGroup.objects.get(pk=group_id)
        self.assertEqual(group.display_name, 'IdP Rename Me')

    def test_scim_manual_name_collision_records_provisioning_event_and_status(self):
        CompanyGroup.objects.create(company=self.company, display_name='Audit Manual')
        response = self.scim_client.post(
            f'/api/v1/companies/{self.company.slug}/scim/v2/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'Audit Manual',
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=f'Bearer {self.scim_token}',
        )
        self.assertEqual(response.status_code, 409, response.content)

        event = ScimProvisioningEvent.objects.get(company=self.company)
        self.assertEqual(event.event_type, ScimProvisioningEvent.TYPE_GROUP_DISPLAY_NAME_CONFLICT)
        self.assertEqual(event.channel, ScimProvisioningEvent.CHANNEL_SCIM)
        self.assertEqual(event.detail['display_name'], 'Audit Manual')
        self.assertEqual(event.detail['conflicting_group_source'], CompanyGroup.SOURCE_MANUAL)
        self.assertEqual(event.detail['operation'], 'create')
        self.assertEqual(event.detail['http_status'], 409)
        self.assertIsNotNone(event.scim_token_id)

        self._as_owner()
        status = self.client.get(self._admin_url('/api/v1/scim'))
        self.assertEqual(status.status_code, 200, status.data)
        self.assertIsNotNone(status.data['last_provisioning_error'])
        self.assertEqual(status.data['last_provisioning_error']['code'], 409)
        self.assertEqual(
            status.data['last_provisioning_error']['type'],
            ScimProvisioningEvent.TYPE_GROUP_DISPLAY_NAME_CONFLICT,
        )
        self.assertEqual(len(status.data['recent_provisioning_events']), 1)

    def test_admin_scim_name_collision_records_provisioning_event(self):
        create = self.scim_client.post(
            f'/api/v1/companies/{self.company.slug}/scim/v2/Groups',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                    'displayName': 'Admin Audit Clash',
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=f'Bearer {self.scim_token}',
        )
        self.assertEqual(create.status_code, 201, create.content)

        self._as_owner()
        response = self.client.post(
            self._admin_url('/api/v1/groups'),
            {'display_name': 'Admin Audit Clash'},
            format='json',
        )
        self.assertEqual(response.status_code, 409, response.data)

        event = ScimProvisioningEvent.objects.filter(company=self.company).latest('created_at')
        self.assertEqual(event.channel, ScimProvisioningEvent.CHANNEL_ADMIN)
        self.assertEqual(event.detail['operation'], 'create')
        self.assertEqual(event.detail['conflicting_group_source'], CompanyGroup.SOURCE_SCIM)
