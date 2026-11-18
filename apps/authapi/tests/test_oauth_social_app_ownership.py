"""Company OAuth client updates cannot take over another company's SocialApp."""

from allauth.socialaccount.models import SocialApp
from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework.test import APIClient, APITestCase

from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthClient

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1'],
    AUTH_RATE_LIMIT_ENABLED=False,
    JWT_ISSUER='https://auth.example.com',
)
class OAuthSocialAppOwnershipTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.company_a = Company.objects.create(name='Company A', slug='company-a')
        self.company_b = Company.objects.create(name='Company B', slug='company-b')
        self.owner_b = User.objects.create_user(
            username='owner-b',
            email='owner-b@example.com',
            password='x',
        )
        self.company_b.owners.add(self.owner_b)
        set_company_access(self.company_b, self.owner_b, enabled=True)
        self.client.force_authenticate(user=self.owner_b)
        self.app_a = self._app(self.company_a, suffix='a')
        self.app_b = self._app(self.company_b, suffix='b')
        self.client_a = CompanyOAuthClient.objects.create(
            company=self.company_a,
            social_app=self.app_a,
            is_active=True,
        )
        self.client_b = CompanyOAuthClient.objects.create(
            company=self.company_b,
            social_app=self.app_b,
            is_active=True,
        )

    def _app(self, company: Company, *, suffix: str, provider: str = 'github') -> SocialApp:
        return SocialApp.objects.create(
            provider=provider,
            name=f'{provider}-{suffix}',
            client_id=f'cid-{suffix}',
            secret=f'secret-{suffix}',
            settings={'catalog_slug': provider, 'created_by_company_id': company.id},
        )

    def _client_url(self, client_id: int) -> str:
        return f'/api/v1/oauth-clients/{client_id}?company_id={self.company_b.id}'

    def _app_url(self, app_id: int) -> str:
        return f'/api/v1/oauth-social-apps/{app_id}?company_id={self.company_b.id}'

    def test_company_cannot_retarget_oauth_client_at_another_companys_social_app(self):
        response = self.client.put(
            self._client_url(self.client_b.pk),
            {'social_app_id': self.app_a.id},
            format='json',
        )
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            response.data['error'],
            'This SocialApp is already mapped. Create a new OAuth key instead.',
        )
        self.client_b.refresh_from_db()
        self.app_a.refresh_from_db()
        self.assertEqual(self.client_b.social_app_id, self.app_b.id)
        self.assertEqual(self.app_a.secret, 'secret-a')
        self.assertEqual(self.app_a.client_id, 'cid-a')

    def test_company_cannot_attach_unmapped_social_app_created_by_another_company(self):
        self.client_a.delete()
        response = self.client.put(
            self._client_url(self.client_b.pk),
            {'social_app_id': self.app_a.id},
            format='json',
        )
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            response.data['error'],
            'This SocialApp cannot be attached to your company.',
        )
        self.client_b.refresh_from_db()
        self.app_a.refresh_from_db()
        self.assertEqual(self.client_b.social_app_id, self.app_b.id)
        self.assertEqual(self.app_a.secret, 'secret-a')

    def test_company_cannot_edit_foreign_social_app_when_legacy_mapping_exists(self):
        legacy = CompanyOAuthClient.objects.bulk_create(
            [
                CompanyOAuthClient(
                    company=self.company_b,
                    social_app=self.app_a,
                    is_active=True,
                )
            ]
        )[0]
        self.assertTrue(
            CompanyOAuthClient.objects.filter(pk=legacy.pk, company=self.company_b, social_app=self.app_a).exists()
        )

        edited = self.client.put(
            self._app_url(self.app_a.pk),
            {'client_id': 'stolen-id', 'client_secret': 'stolen-secret', 'tenant': 'stolen-tenant'},
            format='json',
        )
        self.assertEqual(edited.status_code, 404, edited.data)
        self.assertEqual(edited.data['error'], 'SocialApp not found.')
        self.app_a.refresh_from_db()
        self.assertEqual(self.app_a.client_id, 'cid-a')
        self.assertEqual(self.app_a.secret, 'secret-a')
        self.assertNotIn('tenant', self.app_a.settings)

        listed = self.client.get(f'/api/v1/oauth-social-apps?company_id={self.company_b.id}')
        self.assertEqual(listed.status_code, 200, listed.data)
        ids = {row['id'] for row in listed.data['social_apps']}
        self.assertIn(self.app_b.id, ids)
        self.assertNotIn(self.app_a.id, ids)

        deleted = self.client.delete(self._app_url(self.app_a.pk))
        self.assertEqual(deleted.status_code, 404, getattr(deleted, 'data', deleted.content))
        self.assertTrue(SocialApp.objects.filter(pk=self.app_a.pk).exists())

    def test_company_cannot_edit_foreign_social_app_when_legacy_mapping_is_the_only_one(self):
        CompanyOAuthClient.objects.filter(pk=self.client_a.pk).delete()
        CompanyOAuthClient.objects.bulk_create(
            [
                CompanyOAuthClient(
                    company=self.company_b,
                    social_app=self.app_a,
                    is_active=True,
                )
            ]
        )
        edited = self.client.put(
            self._app_url(self.app_a.pk),
            {'client_secret': 'stolen-secret'},
            format='json',
        )
        self.assertEqual(edited.status_code, 404, edited.data)
        self.app_a.refresh_from_db()
        self.assertEqual(self.app_a.secret, 'secret-a')

    def test_update_to_own_social_app_still_works(self):
        same = self.client.put(
            self._client_url(self.client_b.pk),
            {'social_app_id': self.app_b.id, 'is_active': True},
            format='json',
        )
        self.assertEqual(same.status_code, 200, same.data)
        self.assertEqual(same.data['social_app_id'], self.app_b.id)

        owned = self._app(self.company_b, suffix='b-google', provider='google')
        switched = self.client.put(
            self._client_url(self.client_b.pk),
            {'social_app_id': owned.id},
            format='json',
        )
        self.assertEqual(switched.status_code, 200, switched.data)
        self.client_b.refresh_from_db()
        self.assertEqual(self.client_b.social_app_id, owned.id)

        edited = self.client.put(
            self._app_url(owned.pk),
            {'client_secret': 'rotated-secret'},
            format='json',
        )
        self.assertEqual(edited.status_code, 200, edited.data)
        owned.refresh_from_db()
        self.assertEqual(owned.secret, 'rotated-secret')
