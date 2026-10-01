from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.models import ActionOutbox, ActionRule
from apps.authapi.models import RefreshTokenSession
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyGroup, CompanyMembership

User = get_user_model()


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    AUTH_RATE_LIMIT_ENABLED=False,
)
class AdminUserDeleteTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Delete Co', slug='delete-co')
        self.other_company = Company.objects.create(name='Other Co', slug='other-co')
        ActionRule.objects.create(
            company=self.company,
            name='Deleted',
            event_type='identity.user.deleted',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        self.owner = User.objects.create_user(username='owner', email='owner@del.com', password='x')
        self.target = User.objects.create_user(username='target', email='target@del.com', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.target, enabled=True)
        self.company.owners.add(self.owner)
        self.client.force_authenticate(user=self.owner)

    def _delete(self, user_id):
        return self.client.delete(f'/api/v1/users/{user_id}?company_id={self.company.pk}')

    def test_deletes_account_when_last_company(self):
        target_id = self.target.pk
        response = self._delete(target_id)
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.assertFalse(User.objects.filter(pk=target_id).exists())
        event = ActionOutbox.objects.get(event_type='identity.user.deleted', company=self.company)
        self.assertEqual(event.envelope['data']['source'], 'admin')

    def test_keeps_account_for_other_companies(self):
        set_company_access(self.other_company, self.target, enabled=True)
        response = self._delete(self.target.pk)
        self.assertEqual(response.status_code, 204)
        self.assertTrue(User.objects.filter(pk=self.target.pk).exists())
        self.assertFalse(CompanyMembership.objects.filter(user=self.target, company=self.company).exists())
        self.assertTrue(
            CompanyMembership.objects.filter(user=self.target, company=self.other_company).exists()
        )

    def test_other_company_data_is_untouched(self):
        set_company_access(self.other_company, self.target, enabled=True)
        self.other_company.owners.add(self.target)
        other_group = CompanyGroup.objects.create(
            company=self.other_company,
            display_name='Other team',
            source=CompanyGroup.SOURCE_MANUAL,
        )
        other_group.members.add(self.target)
        _issue_shellui_tokens(self.target, company=self.company)
        _issue_shellui_tokens(self.target, company=self.other_company)

        response = self._delete(self.target.pk)

        self.assertEqual(response.status_code, 204)
        self.assertTrue(User.objects.filter(pk=self.target.pk).exists())
        self.assertFalse(self.company.members.filter(pk=self.target.pk).exists())
        self.assertTrue(self.other_company.members.filter(pk=self.target.pk).exists())
        self.assertTrue(self.other_company.owners.filter(pk=self.target.pk).exists())
        self.assertTrue(other_group.members.filter(pk=self.target.pk).exists())
        self.assertFalse(RefreshTokenSession.objects.filter(user=self.target, company=self.company).exists())
        self.assertTrue(
            RefreshTokenSession.objects.filter(
                user=self.target,
                company=self.other_company,
                revoked_at__isnull=True,
            ).exists()
        )
        self.assertFalse(
            ActionOutbox.objects.filter(event_type='identity.user.deleted', company=self.other_company).exists()
        )

    def test_keeps_account_when_owner_elsewhere_without_membership(self):
        co_owner = User.objects.create_user(username='co', email='co@del.com', password='x')
        self.other_company.owners.add(self.target, co_owner)
        response = self._delete(self.target.pk)
        self.assertEqual(response.status_code, 204)
        self.assertTrue(User.objects.filter(pk=self.target.pk).exists())
        self.assertTrue(self.other_company.owners.filter(pk=self.target.pk).exists())

    def test_keeps_account_when_in_other_company_group_without_membership(self):
        other_group = CompanyGroup.objects.create(
            company=self.other_company,
            display_name='Legacy',
            source=CompanyGroup.SOURCE_MANUAL,
        )
        other_group.members.add(self.target)
        response = self._delete(self.target.pk)
        self.assertEqual(response.status_code, 204)
        self.assertTrue(User.objects.filter(pk=self.target.pk).exists())
        self.assertTrue(other_group.members.filter(pk=self.target.pk).exists())

    def test_sole_owner_of_other_company_can_be_deleted_here(self):
        set_company_access(self.other_company, self.target, enabled=True)
        self.other_company.owners.add(self.target)
        response = self._delete(self.target.pk)
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.assertTrue(User.objects.filter(pk=self.target.pk).exists())
        self.assertEqual(list(self.other_company.owners.all()), [self.target])

    def test_co_owner_of_current_company_can_be_deleted(self):
        self.company.owners.add(self.target)
        response = self._delete(self.target.pk)
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.assertEqual(list(self.company.owners.all()), [self.owner])

    def test_cannot_delete_self(self):
        self.company.owners.add(self.target)
        response = self._delete(self.owner.pk)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(User.objects.filter(pk=self.owner.pk).exists())

    def test_owner_cannot_delete_staff(self):
        self.target.is_staff = True
        self.target.save(update_fields=['is_staff'])
        response = self._delete(self.target.pk)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(User.objects.filter(pk=self.target.pk).exists())

    def test_cannot_delete_sole_owner(self):
        staff = User.objects.create_user(username='staff', email='staff@del.com', password='x', is_staff=True)
        set_company_access(self.company, staff, enabled=True)
        self.client.force_authenticate(user=staff)
        response = self._delete(self.owner.pk)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error_code'], 'last_company_owner')
        self.assertTrue(User.objects.filter(pk=self.owner.pk).exists())

    def test_non_owner_forbidden(self):
        member = User.objects.create_user(username='member', email='member@del.com', password='x')
        set_company_access(self.company, member, enabled=True)
        self.client.force_authenticate(user=member)
        response = self._delete(self.target.pk)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(User.objects.filter(pk=self.target.pk).exists())

    def test_user_outside_company_not_found(self):
        stranger = User.objects.create_user(username='stranger', email='s@del.com', password='x')
        set_company_access(self.other_company, stranger, enabled=True)
        response = self._delete(stranger.pk)
        self.assertEqual(response.status_code, 404)
        self.assertTrue(User.objects.filter(pk=stranger.pk).exists())
