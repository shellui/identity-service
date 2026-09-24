from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.actions.models import ActionOutbox, ActionRule
from apps.authapi.models import PersonalAccessToken, RefreshTokenSession
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyMembership

User = get_user_model()


class SelfServiceAccountDeleteTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Erase Co', slug='erase-co')
        self.other_company = Company.objects.create(name='Other Erase', slug='other-erase')
        for company in (self.company, self.other_company):
            ActionRule.objects.create(
                company=company,
                name='Deleted',
                event_type='identity.user.deleted',
                action_kind=ActionRule.ACTION_EMAIL,
                config={'recipients': [f'ops@{company.slug}.test']},
            )
        self.user = User.objects.create_user(
            username='erase-me',
            email='erase@example.com',
            password='secret',
        )
        set_company_access(self.company, self.user, enabled=True)
        set_company_access(self.other_company, self.user, enabled=True)
        self.other_user = User.objects.create_user(
            username='stay',
            email='stay@example.com',
            password='secret',
        )
        set_company_access(self.company, self.other_user, enabled=True)

    def _tokens(self, user=None, company=None) -> dict:
        return _issue_shellui_tokens(user or self.user, company=company or self.company)

    def test_happy_path_deletes_user_and_memberships(self):
        tokens = self._tokens()
        user_id = self.user.pk
        response = self.client.delete(
            '/api/v1/user',
            {'confirm': True, 'refresh_token': tokens['refresh_token']},
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
            format='json',
        )
        self.assertEqual(response.status_code, 204, getattr(response, 'data', response.content))
        self.assertFalse(User.objects.filter(pk=user_id).exists())
        self.assertEqual(CompanyMembership.objects.filter(user_id=user_id).count(), 0)
        self.assertEqual(
            ActionOutbox.objects.filter(event_type='identity.user.deleted', company=self.company).count(),
            1,
        )
        self.assertEqual(
            ActionOutbox.objects.filter(event_type='identity.user.deleted', company=self.other_company).count(),
            1,
        )
        payload = ActionOutbox.objects.filter(
            event_type='identity.user.deleted',
            company=self.company,
        ).first().envelope['data']
        self.assertEqual(payload['source'], 'self')
        self.assertEqual(payload['email'], 'erase@example.com')

        profile = self.client.get(
            '/api/v1/user',
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
        )
        self.assertEqual(profile.status_code, 401)

    def test_unauthenticated_rejected(self):
        response = self.client.delete('/api/v1/user', {'confirm': True}, format='json')
        self.assertEqual(response.status_code, 401)

    def test_confirm_required(self):
        tokens = self._tokens()
        missing = self.client.delete(
            '/api/v1/user',
            {},
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
            format='json',
        )
        self.assertEqual(missing.status_code, 400)
        false_confirm = self.client.delete(
            '/api/v1/user',
            {'confirm': False},
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
            format='json',
        )
        self.assertEqual(false_confirm.status_code, 400)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    def test_only_authenticated_subject_deleted(self):
        victim_tokens = self._tokens()
        actor_tokens = self._tokens(user=self.other_user)
        victim_id = self.user.pk
        response = self.client.delete(
            '/api/v1/user',
            {'confirm': True},
            HTTP_AUTHORIZATION=f'Bearer {actor_tokens["access_token"]}',
            format='json',
        )
        self.assertEqual(response.status_code, 204)
        self.assertTrue(User.objects.filter(pk=victim_id).exists())
        self.assertFalse(User.objects.filter(pk=self.other_user.pk).exists())

    def test_revokes_refresh_sessions_and_pats(self):
        tokens = self._tokens()
        RefreshTokenSession.objects.filter(user=self.user).update(revoked_at=None)
        pat_row, pat_secret = self._create_pat()
        response = self.client.delete(
            '/api/v1/user',
            {'confirm': True},
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
            format='json',
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(RefreshTokenSession.objects.filter(user_id=self.user.pk).exists())
        self.assertFalse(PersonalAccessToken.objects.filter(pk=pat_row.pk).exists())

        pat_profile = self.client.get(
            '/api/v1/user',
            HTTP_AUTHORIZATION=f'Bearer {pat_secret}',
        )
        self.assertEqual(pat_profile.status_code, 401)

    def _create_pat(self):
        from apps.authapi.views import _issue_personal_access_token

        return _issue_personal_access_token(
            self.user,
            self.company,
            read_only=False,
            access_global_metrics=False,
            name='test',
        )
