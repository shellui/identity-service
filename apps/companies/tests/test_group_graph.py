from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.companies.access import set_company_access
from apps.companies.group_graph import (
    NestedGroupCycleError,
    assert_nested_group_link_allowed,
    effective_user_ids_for_group,
    would_create_group_cycle,
)
from apps.companies.models import Company, CompanyGroup

User = get_user_model()


class GroupGraphTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Co', slug='co')
        self.other = Company.objects.create(name='Other', slug='other')
        self.user = User.objects.create_user(username='u1', email='u1@co.com', password='x')
        set_company_access(self.company, self.user, enabled=True)

    def test_effective_users_nested(self):
        child = CompanyGroup.objects.create(company=self.company, display_name='Child')
        child.members.add(self.user)
        parent = CompanyGroup.objects.create(company=self.company, display_name='Parent')
        parent.member_groups.add(child)

        self.assertEqual(effective_user_ids_for_group(parent), {self.user.pk})
        self.assertEqual(effective_user_ids_for_group(child), {self.user.pk})

    def test_reject_self_and_cycle(self):
        a = CompanyGroup.objects.create(company=self.company, display_name='A')
        b = CompanyGroup.objects.create(company=self.company, display_name='B')
        a.member_groups.add(b)

        self.assertTrue(would_create_group_cycle(a, a))
        self.assertTrue(would_create_group_cycle(b, a))

        with self.assertRaises(NestedGroupCycleError):
            assert_nested_group_link_allowed(b, a)

    def test_cross_company_nested_rejected(self):
        a = CompanyGroup.objects.create(company=self.company, display_name='A')
        b = CompanyGroup.objects.create(company=self.other, display_name='B')
        with self.assertRaises(NestedGroupCycleError):
            assert_nested_group_link_allowed(a, b)
