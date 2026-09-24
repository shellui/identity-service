import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.tokens import ShellUIAccessToken
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyGroup
from apps.scim.models import CompanyScimToken
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
        scim_child = CompanyGroup.objects.create(
            company=self.company,
            display_name='ScimChild',
            source=CompanyGroup.SOURCE_SCIM,
        )
        scim_parent = CompanyGroup.objects.create(
            company=self.company,
            display_name='ScimParent',
            source=CompanyGroup.SOURCE_SCIM,
        )
        scim_child.members.add(self.user)
        scim_parent.member_groups.add(scim_child)

        tokens = _issue_shellui_tokens(self.user, company=self.company)
        access = ShellUIAccessToken(tokens['access_token'])
        self.assertEqual(
            sorted(access['user_metadata']['groups']),
            sorted(['ManualLeaf', 'ScimChild', 'ScimParent']),
        )
