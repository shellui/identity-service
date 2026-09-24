from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.scim.models import CompanyScimToken
from apps.scim.tokens import generate_scim_token, hash_scim_token

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    SCIM_ENABLED=True,
)
class ScimAdminApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Scim Co', slug='scim-co')
        self.other = Company.objects.create(name='Other Co', slug='other-co')
        self.owner = User.objects.create_user(username='owner', email='owner@example.com', password='x')
        self.member = User.objects.create_user(username='member', email='member@example.com', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.member, enabled=True)
        set_company_access(self.other, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.company.members.add(self.owner, self.member)

    def _as_owner(self):
        self.client.force_authenticate(user=self.owner)

    def _url(self, path: str, company=None) -> str:
        cid = (company or self.company).id
        sep = '&' if '?' in path else '?'
        return f'{path}{sep}company_id={cid}'

    def test_status_reflects_enabled_and_configuration(self):
        self._as_owner()
        status = self.client.get(self._url('/api/v1/scim'))
        self.assertEqual(status.status_code, 200, status.data)
        self.assertTrue(status.data['enabled'])
        self.assertIn('/api/v1/companies/scim-co/scim/v2/', status.data['base_url'])
        self.assertFalse(status.data['configured'])
        self.assertEqual(status.data['active_token_count'], 0)
        self.assertFalse(status.data['directory_read_only'])
        self.assertFalse(status.data['scim_groups_read_only'])

        create = self.client.post(self._url('/api/v1/scim/tokens'), {'name': 'IdP prod'}, format='json')
        self.assertEqual(create.status_code, 201, create.data)
        self.assertIn('token', create.data)
        self.assertEqual(len(create.data['token']), len(create.data['token'].strip()))

        status2 = self.client.get(self._url('/api/v1/scim'))
        self.assertTrue(status2.data['configured'])
        self.assertEqual(status2.data['active_token_count'], 1)
        self.assertFalse(status2.data['directory_read_only'])
        self.assertTrue(status2.data['scim_groups_read_only'])

    def test_member_forbidden(self):
        self.client.force_authenticate(user=self.member)
        for method, path, body in (
            ('get', '/api/v1/scim', None),
            ('get', '/api/v1/scim/tokens', None),
            ('post', '/api/v1/scim/tokens', {'name': 'nope'}),
        ):
            if method == 'get':
                response = self.client.get(self._url(path))
            else:
                response = self.client.post(self._url(path), body or {}, format='json')
            self.assertEqual(response.status_code, 403, (method, path, response.data))

    def test_list_never_returns_secret(self):
        self._as_owner()
        _raw, prefix, digest = generate_scim_token()
        CompanyScimToken.objects.create(
            company=self.company,
            token_prefix=prefix,
            token_hash=digest,
            name='existing',
        )
        listing = self.client.get(self._url('/api/v1/scim/tokens'))
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.data['results']), 1)
        row = listing.data['results'][0]
        self.assertEqual(row['token_prefix'], prefix)
        self.assertNotIn('token', row)
        self.assertNotIn('token_hash', row)
        self.assertTrue(row['is_active'])

    def test_create_shows_secret_once(self):
        self._as_owner()
        created = self.client.post(self._url('/api/v1/scim/tokens'), {}, format='json')
        self.assertEqual(created.status_code, 201)
        secret = created.data['token']
        listing = self.client.get(self._url('/api/v1/scim/tokens'))
        self.assertNotIn('token', listing.data['results'][0])
        row = CompanyScimToken.objects.get(company=self.company)
        self.assertEqual(row.token_hash, hash_scim_token(secret))

    def test_revoke_idempotent_and_cross_company_isolation(self):
        self._as_owner()
        other_token = CompanyScimToken.objects.create(
            company=self.other,
            token_prefix='othprefix12',
            token_hash='a' * 64,
            name='other',
        )
        create = self.client.post(self._url('/api/v1/scim/tokens'), {'name': 'mine'}, format='json')
        token_id = create.data['id']
        missing = self.client.post(self._url(f'/api/v1/scim/tokens/{other_token.id}/revoke', company=self.company))
        self.assertEqual(missing.status_code, 404)
        revoked = self.client.post(self._url(f'/api/v1/scim/tokens/{token_id}/revoke'))
        self.assertEqual(revoked.status_code, 200)
        self.assertFalse(revoked.data['is_active'])
        again = self.client.post(self._url(f'/api/v1/scim/tokens/{token_id}/revoke'))
        self.assertEqual(again.status_code, 200)
        self.assertFalse(again.data['is_active'])

    @override_settings(SCIM_ENABLED=False)
    def test_create_blocked_when_scim_disabled(self):
        self._as_owner()
        status = self.client.get(self._url('/api/v1/scim'))
        self.assertEqual(status.status_code, 200)
        self.assertFalse(status.data['enabled'])
        blocked = self.client.post(self._url('/api/v1/scim/tokens'), {}, format='json')
        self.assertEqual(blocked.status_code, 403)
        self.assertIn('not enabled', blocked.data['error'].lower())

    @override_settings(SCIM_ENABLED=False)
    def test_list_and_revoke_when_scim_disabled(self):
        self._as_owner()
        row = CompanyScimToken.objects.create(
            company=self.company,
            token_prefix='leftover12',
            token_hash='b' * 64,
            name='leftover',
        )
        listing = self.client.get(self._url('/api/v1/scim/tokens'))
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.data['results']), 1)
        revoked = self.client.post(self._url(f'/api/v1/scim/tokens/{row.id}/revoke'))
        self.assertEqual(revoked.status_code, 200)
