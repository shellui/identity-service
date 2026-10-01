from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.actions.models import ActionOutbox, ActionRule
from apps.authapi.models import LoginEvent, PersonalAccessToken, RefreshTokenSession
from apps.authapi.tokens import ShellUIAccessToken
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyGroup, CompanyMembership

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
                action_kind=ActionRule.ACTION_WEBHOOK,
                config={'url': 'https://example.com/h', 'secret': 's'},
            )
        self.user = User.objects.create_user(
            username='erase-me',
            email='erase@example.com',
            password='secret',
        )
        set_company_access(self.company, self.user, enabled=True)
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

    def test_personal_access_token_cannot_delete_account(self):
        _pat_row, pat_secret = self._create_pat()
        response = self.client.delete(
            '/api/v1/user',
            {'confirm': True},
            HTTP_AUTHORIZATION=f'Bearer {pat_secret}',
            format='json',
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    def test_stale_access_token_rejected(self):
        access = ShellUIAccessToken.for_user(self.user)
        access['company_id'] = self.company.id
        access['auth_time'] = int((timezone.now() - timedelta(minutes=10)).timestamp())
        response = self.client.delete(
            '/api/v1/user',
            {'confirm': True},
            HTTP_AUTHORIZATION=f'Bearer {str(access)}',
            format='json',
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error_code'], 'recent_login_required')
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    @override_settings(SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE=timedelta(minutes=30))
    def test_recent_access_token_allowed_within_configured_window(self):
        access = ShellUIAccessToken.for_user(self.user)
        access['company_id'] = self.company.id
        access['auth_time'] = int((timezone.now() - timedelta(minutes=10)).timestamp())
        user_id = self.user.pk
        response = self.client.delete(
            '/api/v1/user',
            {'confirm': True},
            HTTP_AUTHORIZATION=f'Bearer {str(access)}',
            format='json',
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(User.objects.filter(pk=user_id).exists())

    def test_refresh_preserves_auth_time(self):
        tokens = self._tokens()
        import jwt

        decoded = jwt.decode(
            tokens['access_token'],
            options={'verify_signature': False},
            algorithms=['HS256'],
        )
        original_auth_time = decoded['auth_time']
        refreshed = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': tokens['refresh_token']},
            format='json',
        )
        self.assertEqual(refreshed.status_code, 200)
        new_access = jwt.decode(
            refreshed.data['access_token'],
            options={'verify_signature': False},
            algorithms=['HS256'],
        )
        self.assertEqual(new_access['auth_time'], original_auth_time)

    @override_settings(SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE=timedelta(seconds=0))
    def test_refreshed_token_with_old_auth_time_gets_403(self):
        tokens = self._tokens()
        import jwt
        from apps.authapi.tokens import ShellUIRefreshToken

        refresh = ShellUIRefreshToken(tokens['refresh_token'])
        refresh['auth_time'] = int((timezone.now() - timedelta(hours=2)).timestamp())
        refresh['company_id'] = self.company.id
        stale_refresh = str(refresh)
        refreshed = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': stale_refresh},
            format='json',
        )
        self.assertEqual(refreshed.status_code, 200)
        delete_resp = self.client.delete(
            '/api/v1/user',
            {'confirm': True},
            HTTP_AUTHORIZATION=f'Bearer {refreshed.data["access_token"]}',
            format='json',
        )
        self.assertEqual(delete_resp.status_code, 403)

    def test_multi_company_membership_removes_only_current_company(self):
        set_company_access(self.other_company, self.user, enabled=True)
        group = CompanyGroup.objects.create(company=self.company, display_name='Team')
        other_group = CompanyGroup.objects.create(company=self.other_company, display_name='Team')
        group.members.add(self.user)
        other_group.members.add(self.user)
        self.company.owners.add(self.user, self.other_user)
        self.other_company.owners.add(self.user)
        other_tokens = self._tokens(company=self.other_company)
        tokens = self._tokens()

        response = self.client.delete(
            '/api/v1/user',
            {'confirm': True},
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
            format='json',
        )

        self.assertEqual(response.status_code, 204, getattr(response, 'data', response.content))
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())
        self.assertEqual(
            list(self.user.company_memberships.values_list('company_id', flat=True)),
            [self.other_company.id],
        )
        self.assertFalse(group.members.filter(pk=self.user.pk).exists())
        self.assertTrue(other_group.members.filter(pk=self.user.pk).exists())
        self.assertFalse(self.company.owners.filter(pk=self.user.pk).exists())
        self.assertTrue(self.other_company.owners.filter(pk=self.user.pk).exists())
        self.assertFalse(
            RefreshTokenSession.objects.filter(user=self.user, company=self.company).exists()
        )
        self.assertTrue(
            RefreshTokenSession.objects.filter(
                user=self.user,
                company=self.other_company,
                revoked_at__isnull=True,
            ).exists()
        )
        self.assertEqual(
            ActionOutbox.objects.filter(event_type='identity.user.deleted', company=self.company).count(),
            1,
        )
        self.assertEqual(
            ActionOutbox.objects.filter(
                event_type='identity.user.deleted',
                company=self.other_company,
            ).count(),
            0,
        )

        removed_profile = self.client.get(
            '/api/v1/user',
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
        )
        self.assertEqual(removed_profile.status_code, 401)
        refreshed = self.client.post(
            '/api/v1/token?grant_type=refresh_token',
            {'refresh_token': other_tokens['refresh_token']},
            format='json',
        )
        self.assertEqual(refreshed.status_code, 200, getattr(refreshed, 'data', refreshed.content))

    def test_multi_company_removal_keeps_other_company_pat_and_detaches_login_events(self):
        set_company_access(self.other_company, self.user, enabled=True)
        own_pat, _ = self._create_pat()
        from apps.authapi.views import _issue_personal_access_token

        other_pat, _ = _issue_personal_access_token(
            self.user,
            self.other_company,
            read_only=False,
            access_global_metrics=False,
            name='other',
        )
        own_event = LoginEvent.objects.create(
            user=self.user,
            company=self.company,
            outcome=LoginEvent.OUTCOME_SUCCESS,
            provider='github',
        )
        other_event = LoginEvent.objects.create(
            user=self.user,
            company=self.other_company,
            outcome=LoginEvent.OUTCOME_SUCCESS,
            provider='github',
        )
        tokens = self._tokens()

        response = self.client.delete(
            '/api/v1/user',
            {'confirm': True},
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
            format='json',
        )

        self.assertEqual(response.status_code, 204)
        self.assertFalse(PersonalAccessToken.objects.filter(pk=own_pat.pk).exists())
        self.assertTrue(PersonalAccessToken.objects.filter(pk=other_pat.pk).exists())
        own_event.refresh_from_db()
        other_event.refresh_from_db()
        self.assertIsNone(own_event.user_id)
        self.assertEqual(other_event.user_id, self.user.pk)

    def _delete(self, tokens):
        return self.client.delete(
            '/api/v1/user',
            {'confirm': True, 'refresh_token': tokens['refresh_token']},
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
            format='json',
        )

    def test_sole_owner_cannot_delete_account(self):
        self.company.owners.add(self.user)
        tokens = self._tokens()

        response = self._delete(tokens)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error_code'], 'last_company_owner')
        self.assertEqual(response.data['companies'], [{'id': self.company.id, 'name': 'Erase Co'}])
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())
        self.assertTrue(self.company.owners.filter(pk=self.user.pk).exists())
        self.assertFalse(ActionOutbox.objects.filter(event_type='identity.user.deleted').exists())
        still_valid = self.client.get(
            '/api/v1/user',
            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}',
        )
        self.assertEqual(still_valid.status_code, 200)

    def test_sole_owner_check_runs_before_recent_login_check(self):
        self.company.owners.add(self.user)
        access = ShellUIAccessToken.for_user(self.user)
        access['company_id'] = self.company.id
        access['auth_time'] = int((timezone.now() - timedelta(minutes=10)).timestamp())

        response = self.client.delete(
            '/api/v1/user',
            {'confirm': True},
            HTTP_AUTHORIZATION=f'Bearer {str(access)}',
            format='json',
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error_code'], 'last_company_owner')

    def test_co_owner_can_delete_account(self):
        self.company.owners.add(self.user, self.other_user)

        response = self._delete(self._tokens())

        self.assertEqual(response.status_code, 204)
        self.assertEqual(list(self.company.owners.values_list('pk', flat=True)), [self.other_user.pk])

    def test_sole_owner_cannot_leave_company_with_other_memberships(self):
        set_company_access(self.other_company, self.user, enabled=True)
        self.company.owners.add(self.user)

        response = self._delete(self._tokens())

        self.assertEqual(response.status_code, 409)
        self.assertTrue(
            CompanyMembership.objects.filter(user=self.user, company=self.company).exists()
        )

    def test_sole_owner_elsewhere_can_leave_current_company(self):
        set_company_access(self.other_company, self.user, enabled=True)
        self.other_company.owners.add(self.user)

        response = self._delete(self._tokens())

        self.assertEqual(response.status_code, 204)
        self.assertTrue(self.other_company.owners.filter(pk=self.user.pk).exists())

    def test_full_delete_blocked_when_sole_owner_of_another_company(self):
        self.other_company.owners.add(self.user)

        response = self._delete(self._tokens())

        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.data['companies'],
            [{'id': self.other_company.id, 'name': 'Other Erase'}],
        )
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    def _create_pat(self):
        from apps.authapi.views import _issue_personal_access_token

        return _issue_personal_access_token(
            self.user,
            self.company,
            read_only=False,
            access_global_metrics=False,
            name='test',
        )
