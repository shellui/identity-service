"""is_staff and is_superuser can only be changed in Django admin, never through a REST API."""

import json

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.scim.models import CompanyScimToken
from apps.scim.tokens import generate_scim_token

User = get_user_model()

_ESCALATION_BODIES = (
    {'is_staff': True},
    {'is_superuser': True},
    {'is_staff': True, 'is_superuser': True},
    {'is_staff': True, 'first_name': 'Still'},
    {'is_staff': 'true'},
    {'is_superuser': 1},
)


@override_settings(ALLOWED_HOSTS=['testserver'], AUTH_RATE_LIMIT_ENABLED=False)
class AdminOnlyUserFieldsTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Flags Co', slug='flags-co')
        self.staff = User.objects.create_user(username='ops', email='ops@flags.test', password='x', is_staff=True)
        self.owner = User.objects.create_user(username='owner', email='owner@flags.test', password='x')
        self.member = User.objects.create_user(username='member', email='member@flags.test', password='x')
        for user in (self.staff, self.owner, self.member):
            set_company_access(self.company, user, enabled=True)
        self.company.owners.add(self.owner)

    def _client(self, user) -> APIClient:
        client = APIClient()
        tokens = _issue_shellui_tokens(user, company=self.company)
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
        return client

    def _users_url(self, user) -> str:
        return f'/api/v1/users/{user.pk}?company_id={self.company.pk}'

    def _assert_flags(self, user, *, is_staff: bool, is_superuser: bool = False) -> None:
        user.refresh_from_db()
        self.assertIs(user.is_staff, is_staff)
        self.assertIs(user.is_superuser, is_superuser)

    def test_put_users_detail_refuses_flags_for_staff_and_owner_callers(self):
        for actor in (self.staff, self.owner):
            client = self._client(actor)
            for target in (self.member, self.owner, actor):
                for body in _ESCALATION_BODIES:
                    with self.subTest(actor=actor.username, target=target.username, body=body):
                        response = client.put(self._users_url(target), body, format='json')
                        self.assertEqual(response.status_code, 400, response.data)
                        self.assertEqual(response.data['error_code'], 'admin_only_field')
                        target.refresh_from_db()
                        self.assertIs(target.is_superuser, False)
                        self.assertIs(target.is_staff, target.pk == self.staff.pk)
        # The refused body changed nothing else either.
        self.member.refresh_from_db()
        self.assertEqual(self.member.first_name, '')

    def test_staff_cannot_remove_own_or_other_staff_flag(self):
        other_staff = User.objects.create_user(username='ops2', email='ops2@flags.test', password='x', is_staff=True)
        set_company_access(self.company, other_staff, enabled=True)
        client = self._client(self.staff)
        for target in (self.staff, other_staff):
            response = client.put(self._users_url(target), {'is_staff': False}, format='json')
            self.assertEqual(response.status_code, 400, response.data)
            self._assert_flags(target, is_staff=True)

    def test_put_users_detail_still_updates_allowed_fields(self):
        client = self._client(self.owner)
        response = client.put(self._users_url(self.member), {'first_name': 'Ada'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.member.refresh_from_db()
        self.assertEqual(self.member.first_name, 'Ada')
        self.assertIn('is_staff', response.data)
        self.assertFalse(response.data['is_staff'])

    def test_metadata_data_cannot_claim_flags(self):
        client = self._client(self.staff)
        response = client.put(
            self._users_url(self.member),
            {'data': {'is_staff': True, 'is_superuser': True, 'nickname': 'm'}},
            format='json',
        )
        self.assertEqual(response.status_code, 200, response.data)
        self._assert_flags(self.member, is_staff=False)
        cached = cache.get(f'shellui:user_metadata:{self.member.pk}') or {}
        self.assertFalse(cached.get('is_staff'))
        self.assertNotIn('is_superuser', cached)

    def test_patch_users_detail_is_not_allowed(self):
        for actor in (self.staff, self.owner):
            client = self._client(actor)
            for body in _ESCALATION_BODIES:
                with self.subTest(actor=actor.username, body=body):
                    response = client.patch(self._users_url(self.member), body, format='json')
                    self.assertEqual(response.status_code, 405)
                    self._assert_flags(self.member, is_staff=False)

    def test_self_service_user_endpoints_ignore_flags(self):
        for actor in (self.member, self.owner, self.staff):
            client = self._client(actor)
            expected_staff = actor.pk == self.staff.pk
            for body in _ESCALATION_BODIES:
                with self.subTest(actor=actor.username, body=body):
                    put = client.put(
                        f'/api/v1/user?company_id={self.company.pk}',
                        {**body, 'data': dict(body)},
                        format='json',
                    )
                    self.assertEqual(put.status_code, 200, put.data)
                    self.assertIs(put.data['user_metadata']['is_staff'], expected_staff)
                    self.assertNotIn('is_superuser', put.data['user_metadata'])
                    patch = client.patch(
                        f'/api/v1/user?company_id={self.company.pk}',
                        {**body, 'name': 'Same Name'},
                        format='json',
                    )
                    self.assertEqual(patch.status_code, 200, patch.data)
                    self._assert_flags(actor, is_staff=expected_staff)

    def test_invitation_create_ignores_flags(self):
        client = self._client(self.owner)
        response = client.post(
            f'/api/v1/invitations?company_id={self.company.pk}',
            {'email': 'new@flags.test', 'is_staff': True, 'is_superuser': True},
            format='json',
        )
        self.assertIn(response.status_code, (201, 503), response.data)
        self.assertFalse(User.objects.filter(email='new@flags.test').exists())


@override_settings(SCIM_ENABLED=True, ALLOWED_HOSTS=['testserver'])
class ScimCannotSetAdminFlagsTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company = Company.objects.create(name='Scim Flags', slug='scim-flags')
        raw, prefix, digest = generate_scim_token()
        CompanyScimToken.objects.create(company=self.company, token_prefix=prefix, token_hash=digest, name='t')
        self.auth = f'Bearer {raw}'
        self.base = f'/api/v1/companies/{self.company.pk}/scim/v2'

    def _send(self, method, path, body):
        return getattr(self.client, method)(
            f'{self.base}{path}',
            data=json.dumps(body),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth,
        )

    def test_scim_create_replace_and_patch_never_set_flags(self):
        create = self._send('post', '/Users', {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'idp@scim.test',
            'emails': [{'value': 'idp@scim.test', 'primary': True}],
            'active': True,
            'is_staff': True,
            'is_superuser': True,
        })
        self.assertEqual(create.status_code, 201, create.content)
        user = User.objects.get(pk=json.loads(create.content)['id'])
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

        self._send('put', f'/Users/{user.pk}', {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'idp@scim.test',
            'emails': [{'value': 'idp@scim.test', 'primary': True}],
            'active': True,
            'is_staff': True,
            'is_superuser': True,
        })
        self._send('patch', f'/Users/{user.pk}', {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': [
                {'op': 'replace', 'path': 'is_staff', 'value': True},
                {'op': 'replace', 'value': {'is_superuser': True}},
            ],
        })
        user.refresh_from_db()
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
