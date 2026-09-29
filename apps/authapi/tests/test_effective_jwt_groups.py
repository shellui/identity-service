from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.tokens import ShellUIAccessToken
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyGroup

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    OAUTH_TOKEN_DELIVERY='code',
)
class EffectiveJwtGroupsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Groups Co', slug='groups-co')
        self.user = User.objects.create_user(
            username='groups-user',
            email='groups@example.com',
            password='secret',
        )
        set_company_access(self.company, self.user, enabled=True)

    def _nested_groups(self):
        parent = CompanyGroup.objects.create(company=self.company, display_name='Parent')
        child = CompanyGroup.objects.create(company=self.company, display_name='Child')
        child.members.add(self.user)
        parent.member_groups.add(child)
        return parent, child

    def test_jwt_user_metadata_includes_nested_ancestor_groups(self):
        self._nested_groups()
        tokens = _issue_shellui_tokens(self.user, company=self.company)
        access = ShellUIAccessToken(tokens['access_token'])
        self.assertEqual(access['user_metadata']['groups'], ['Child', 'Parent'])

    def test_user_endpoint_groups_match_effective_membership(self):
        self._nested_groups()
        tokens = _issue_shellui_tokens(self.user, company=self.company)
        response = self.client.get(
            '/api/v1/user',
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['user_metadata']['groups'], ['Child', 'Parent'])
