import json
from urllib.parse import quote

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from apps.authapi.models import PersonalAccessToken, RefreshTokenSession
from apps.authapi.oauth_user import get_or_create_user_for_oauth
from apps.authapi.tokens import ShellUIAccessToken
from apps.companies.access import is_company_access_enabled, set_company_access
from apps.companies.models import Company, CompanyGroup
from apps.scim.filters import ShellUIGroupFilterQuery, ShellUIUserFilterQuery
from apps.scim.provisioner import get_scim_provisioner_user
from apps.scim.tests.test_scim_tenant_isolation import SCIM_ON, _scim_base, _token_for

User = get_user_model()


@override_settings(**SCIM_ON)
class ScimEmailUniquenessTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company_a = Company.objects.create(name='A', slug='a-uniq')
        self.company_b = Company.objects.create(name='B', slug='b-uniq')
        self.auth_a = f'Bearer {_token_for(self.company_a)}'

        self.victim = User.objects.create_user(
            username='victim@example.com',
            email='victim@example.com',
            password='x',
        )
        set_company_access(self.company_b, self.victim, enabled=True)

        self.a_user = User.objects.create_user(
            username='aonly@example.com',
            email='aonly@example.com',
            password='x',
        )
        set_company_access(self.company_a, self.a_user, enabled=True)

    def test_patch_email_to_existing_user_returns_409(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': [
                {
                    'op': 'replace',
                    'path': 'emails',
                    'value': [{'value': 'victim@example.com', 'primary': True}],
                }
            ],
        }
        response = self.client.patch(
            f'{_scim_base(self.company_a)}/Users/{self.a_user.pk}',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 409)
        self.a_user.refresh_from_db()
        self.assertEqual(self.a_user.email, 'aonly@example.com')

    def test_put_email_to_existing_user_returns_409(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'victim@example.com',
            'emails': [{'value': 'victim@example.com', 'primary': True}],
            'active': True,
        }
        response = self.client.put(
            f'{_scim_base(self.company_a)}/Users/{self.a_user.pk}',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 409)


@override_settings(**SCIM_ON)
class ScimLockedIdentityExactMatchTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company = Company.objects.create(name='C', slug='c-lock')
        self.auth = f'Bearer {_token_for(self.company)}'

        self.shared = User.objects.create_user(
            username='shared@example.com',
            email='shared@example.com',
            password='x',
        )
        other = Company.objects.create(name='Other', slug='other-lock')
        set_company_access(self.company, self.shared, enabled=True)
        set_company_access(other, self.shared, enabled=True)

    def test_case_variant_email_change_rejected_for_shared_user(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'SHARED@EXAMPLE.COM',
            'emails': [{'value': 'SHARED@EXAMPLE.COM', 'primary': True}],
            'active': True,
        }
        response = self.client.put(
            f'{_scim_base(self.company)}/Users/{self.shared.pk}',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth,
        )
        self.assertEqual(response.status_code, 409)
        self.shared.refresh_from_db()
        self.assertEqual(self.shared.email, 'shared@example.com')

    def test_trailing_space_username_rejected_for_staff(self):
        staff = User.objects.create_user(
            username='staffuser',
            email='staff@example.com',
            password='x',
            is_staff=True,
        )
        set_company_access(self.company, staff, enabled=True)
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'staffuser ',
            'emails': [{'value': 'staff@example.com', 'primary': True}],
            'active': True,
        }
        response = self.client.put(
            f'{_scim_base(self.company)}/Users/{staff.pk}',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth,
        )
        self.assertEqual(response.status_code, 409)
        staff.refresh_from_db()
        self.assertEqual(staff.username, 'staffuser')


@override_settings(**SCIM_ON)
class ScimOrphanClaimTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company = Company.objects.create(name='ClaimCo', slug='claim-co')
        self.auth = f'Bearer {_token_for(self.company)}'
        self.orphan = User.objects.create_user(
            username='orphan@example.com',
            email='orphan@example.com',
            password='x',
        )

    def test_post_cannot_claim_orphan_user(self):
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'orphan@example.com',
            'emails': [{'value': 'orphan@example.com', 'primary': True}],
            'active': True,
        }
        response = self.client.post(
            f'{_scim_base(self.company)}/Users',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth,
        )
        self.assertEqual(response.status_code, 409)
        self.assertFalse(self.orphan.company_memberships.filter(company=self.company).exists())

    def test_post_cannot_claim_scim_provisioner(self):
        provisioner = get_scim_provisioner_user()
        payload = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': provisioner.username,
            'emails': [{'value': provisioner.email, 'primary': True}],
            'active': True,
        }
        response = self.client.post(
            f'{_scim_base(self.company)}/Users',
            data=json.dumps(payload),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth,
        )
        self.assertEqual(response.status_code, 409)


@override_settings(**SCIM_ON)
class ScimFilterTenantTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company_a = Company.objects.create(name='FA', slug='fa')
        self.company_b = Company.objects.create(name='FB', slug='fb')
        self.auth_a = f'Bearer {_token_for(self.company_a)}'

        self.user_a = User.objects.create_user(username='alice', email='alice@a.com', password='x')
        set_company_access(self.company_a, self.user_a, enabled=True)
        self.user_b = User.objects.create_user(username='bob', email='bob@b.com', password='x')
        set_company_access(self.company_b, self.user_b, enabled=True)

        self.group_a = CompanyGroup.create_scim_provisioned(company=self.company_a, display_name='Team A')
        self.group_b = CompanyGroup.create_scim_provisioned(company=self.company_b, display_name='Team B')

    def test_user_filter_user_name_eq_finds_member(self):
        filt = quote('userName eq "alice"')
        response = self.client.get(
            f'{_scim_base(self.company_a)}/Users?filter={filt}',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 200, response.content)
        ids = {r['id'] for r in json.loads(response.content)['Resources']}
        self.assertEqual(ids, {str(self.user_a.pk)})

    def test_user_or_filter_does_not_leak_other_company(self):
        filt = quote('userName eq "alice" or userName eq "bob"')
        response = self.client.get(
            f'{_scim_base(self.company_a)}/Users?filter={filt}',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 200)
        ids = {r['id'] for r in json.loads(response.content)['Resources']}
        self.assertEqual(ids, {str(self.user_a.pk)})

    def test_group_or_filter_stays_in_company(self):
        filt = quote('displayName eq "Team A" or displayName eq "Team B"')
        response = self.client.get(
            f'{_scim_base(self.company_a)}/Groups?filter={filt}',
            HTTP_AUTHORIZATION=self.auth_a,
        )
        self.assertEqual(response.status_code, 200)
        ids = {r['id'] for r in json.loads(response.content)['Resources']}
        self.assertEqual(ids, {str(self.group_a.pk)})

    def test_filter_sql_wraps_predicate_before_tenant_and(self):
        q = ShellUIUserFilterQuery.query_class(
            'userName eq "a" or userName eq "b"',
            ShellUIUserFilterQuery.table_name(),
            ShellUIUserFilterQuery.attr_map,
            (),
        )
        from django.test import RequestFactory

        request = RequestFactory().get('/')
        request.scim_company = self.company_a
        sql, _params = ShellUIUserFilterQuery.get_raw_args(q, request)
        self.assertIn('WHERE ((', sql)
        self.assertIn('companies_companymembership', sql)

        gq = ShellUIGroupFilterQuery.query_class(
            'displayName eq "x" or displayName eq "y"',
            ShellUIGroupFilterQuery.table_name(),
            ShellUIGroupFilterQuery.attr_map,
            (),
        )
        gsql, _ = ShellUIGroupFilterQuery.get_raw_args(gq, request)
        self.assertIn('WHERE ((', gsql)


class OAuthDuplicateEmailLookupTests(TestCase):
    def test_get_or_create_does_not_raise_with_duplicate_emails(self):
        User.objects.create_user(username='u1', email='dup@example.com', password='x')
        User.objects.create_user(username='u2', email='DUP@example.com', password='x')
        user, created = get_or_create_user_for_oauth(
            email='dup@example.com',
            defaults={'username': 'oauth_x'},
        )
        self.assertFalse(created)
        self.assertEqual(user.email.lower(), 'dup@example.com')


@override_settings(**SCIM_ON)
class ScimDeprovisionRevokesCompanyTokensTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.company = Company.objects.create(name='Dep', slug='dep-co')
        self.auth = f'Bearer {_token_for(self.company)}'

        self.owner = User.objects.create_user(username='owner', email='owner@dep.com', password='x')
        self.company.owners.set([self.owner])
        set_company_access(self.company, self.owner, enabled=True)

        from apps.authapi.refresh_sessions import register_refresh_session
        from apps.authapi.tokens import ShellUIRefreshToken

        refresh = ShellUIRefreshToken.for_user(self.owner)
        refresh['company_id'] = str(self.company.pk)
        register_refresh_session(user=self.owner, company=self.company, refresh=refresh)

        access = ShellUIAccessToken.for_user(self.owner)
        access['company_id'] = str(self.company.pk)
        PersonalAccessToken.objects.create(
            company=self.company,
            user=self.owner,
            jti=str(access['jti']),
            name='admin',
        )

    def test_scim_deactivate_revokes_company_sessions_and_pats(self):
        response = self.client.patch(
            f'{_scim_base(self.company)}/Users/{self.owner.pk}',
            data=json.dumps(
                {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': [{'op': 'replace', 'path': 'active', 'value': False}],
                }
            ),
            content_type='application/scim+json',
            HTTP_AUTHORIZATION=self.auth,
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(is_company_access_enabled(self.company, self.owner))
        self.assertFalse(
            RefreshTokenSession.objects.filter(user=self.owner, company=self.company, revoked_at__isnull=True).exists()
        )
        pat = PersonalAccessToken.objects.get(company=self.company, user=self.owner)
        self.assertIsNotNone(pat.revoked_at)
