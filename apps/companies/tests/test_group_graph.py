from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.companies.access import set_company_access
from apps.companies.group_graph import (
    NestedGroupCycleError,
    assert_nested_group_link_allowed,
    effective_group_display_names_for_user,
    effective_group_ids_for_user,
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

    def test_effective_group_ids_direct_only(self):
        g = CompanyGroup.objects.create(company=self.company, display_name='Direct')
        g.members.add(self.user)
        self.assertEqual(effective_group_ids_for_user(self.user, self.company), {g.pk})
        self.assertEqual(effective_group_display_names_for_user(self.user, self.company), ['Direct'])

    def test_effective_group_ids_nested_ancestors(self):
        a = CompanyGroup.objects.create(company=self.company, display_name='A')
        b = CompanyGroup.objects.create(company=self.company, display_name='B')
        c = CompanyGroup.objects.create(company=self.company, display_name='C')
        c.members.add(self.user)
        b.member_groups.add(c)
        a.member_groups.add(b)

        self.assertEqual(
            effective_group_ids_for_user(self.user, self.company),
            {a.pk, b.pk, c.pk},
        )
        self.assertEqual(
            effective_group_display_names_for_user(self.user, self.company),
            ['A', 'B', 'C'],
        )

    def test_effective_group_ids_cycle_safe(self):
        a = CompanyGroup.objects.create(company=self.company, display_name='A')
        b = CompanyGroup.objects.create(company=self.company, display_name='B')
        a.members.add(self.user)
        a.member_groups.add(b)
        b.member_groups.add(a)

        self.assertEqual(effective_group_ids_for_user(self.user, self.company), {a.pk, b.pk})

    def test_effective_group_ids_excludes_unrelated_branch(self):
        parent = CompanyGroup.objects.create(company=self.company, display_name='Parent')
        child = CompanyGroup.objects.create(company=self.company, display_name='Child')
        sibling = CompanyGroup.objects.create(company=self.company, display_name='Sibling')
        other_user = User.objects.create_user(username='u2', email='u2@co.com', password='x')
        child.members.add(self.user)
        sibling.members.add(other_user)
        parent.member_groups.add(child, sibling)

        self.assertEqual(
            effective_group_display_names_for_user(self.user, self.company),
            ['Child', 'Parent'],
        )

    def test_effective_group_ids_cross_company_excluded(self):
        local = CompanyGroup.objects.create(company=self.company, display_name='Local')
        local.members.add(self.user)
        foreign = CompanyGroup.objects.create(company=self.other, display_name='Foreign')
        foreign.members.add(self.user)

        self.assertEqual(effective_group_ids_for_user(self.user, self.company), {local.pk})
        self.assertEqual(effective_group_ids_for_user(self.user, self.other), {foreign.pk})
