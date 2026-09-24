from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.actions.models import ActionOutbox, ActionRule
from apps.actions.user_hooks import (
    emit_oauth_user_created_if_new,
    emit_user_deleted_for_all_companies,
)
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()


class UserLifecycleEmitTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Life Co', slug='life-co')
        self.other = Company.objects.create(name='Other', slug='other-co')
        ActionRule.objects.create(
            company=self.company,
            name='Created',
            event_type='identity.user.created',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['ops@life.test']},
        )
        for company in (self.company, self.other):
            ActionRule.objects.create(
                company=company,
                name='Deleted',
                event_type='identity.user.deleted',
                action_kind=ActionRule.ACTION_EMAIL,
                config={'recipients': [f'ops@{company.slug}.test']},
            )

    def test_oauth_created_emits_once_for_company(self):
        user = User.objects.create_user(username='new', email='new@life.test', password='x')
        emit_oauth_user_created_if_new(
            self.company,
            user,
            created=True,
            oauth_provider='github',
        )
        emit_oauth_user_created_if_new(
            self.company,
            user,
            created=False,
            oauth_provider='github',
        )
        rows = ActionOutbox.objects.filter(event_type='identity.user.created', company=self.company)
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows.first().envelope['data']['oauth_provider'], 'github')

    def test_delete_emits_per_company_membership(self):
        user = User.objects.create_user(username='gone', email='gone@life.test', password='x')
        set_company_access(self.company, user, enabled=True)
        set_company_access(self.other, user, enabled=True)
        emit_user_deleted_for_all_companies(user, source='admin')
        self.assertEqual(
            ActionOutbox.objects.filter(event_type='identity.user.deleted', company=self.company).count(),
            1,
        )
        self.assertEqual(
            ActionOutbox.objects.filter(event_type='identity.user.deleted', company=self.other).count(),
            1,
        )


class UserAdminDeleteEmitTests(TestCase):
    def setUp(self):
        from django.contrib.admin.sites import AdminSite
        from django.test import RequestFactory

        from apps.authapi.admin import UserAdmin

        self.company = Company.objects.create(name='Del Co', slug='del-co')
        ActionRule.objects.create(
            company=self.company,
            name='Del',
            event_type='identity.user.deleted',
            action_kind=ActionRule.ACTION_EMAIL,
            config={'recipients': ['ops@del.test']},
        )
        self.staff = User.objects.create_superuser(
            username='staff',
            email='staff@del.test',
            password='secret',
        )
        self.admin = UserAdmin(User, AdminSite())
        self.request = RequestFactory().get('/admin/')
        self.request.user = self.staff

    def test_admin_delete_model_emits_before_removal(self):
        user = User.objects.create_user(username='victim', email='victim@del.test', password='x')
        set_company_access(self.company, user, enabled=True)
        with self.captureOnCommitCallbacks(execute=False):
            self.admin.delete_model(self.request, user)
        self.assertFalse(User.objects.filter(pk=user.pk).exists())
        self.assertEqual(
            ActionOutbox.objects.filter(
                event_type='identity.user.deleted',
                company=self.company,
            ).count(),
            1,
        )
