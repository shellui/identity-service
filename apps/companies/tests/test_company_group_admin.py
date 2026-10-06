from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, TestCase
from django.urls import reverse

from apps.actions.models import ActionOutbox, ActionRule, EventLog
from apps.companies.admin import CompanyGroupAdmin, CompanyGroupAdminForm
from apps.companies.models import Company, CompanyGroup

User = get_user_model()


class CompanyGroupAdminTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme')
        self.staff = User.objects.create_superuser(
            username='staff',
            email='staff@acme.com',
            password='secret',
        )
        self.client = Client()
        self.client.force_login(self.staff)
        self.admin_site = AdminSite()
        self.group_admin = CompanyGroupAdmin(CompanyGroup, self.admin_site)
        self.request = RequestFactory().get('/admin/')
        self.request.user = self.staff

    def test_create_form_omits_source_field(self):
        fields = self.group_admin.get_fields(self.request, obj=None)
        self.assertNotIn('source', fields)

    def test_change_form_shows_source_read_only(self):
        group = CompanyGroup.objects.create(company=self.company, display_name='Team')
        readonly = self.group_admin.get_readonly_fields(self.request, obj=group)
        self.assertIn('source', readonly)

    def test_admin_form_forces_manual_on_create(self):
        form = CompanyGroupAdminForm(
            data={
                'company': self.company.pk,
                'display_name': 'Ops',
                'source': CompanyGroup.SOURCE_SCIM,
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data['source'], CompanyGroup.SOURCE_MANUAL)

    def test_admin_create_persists_manual_even_if_posted_scim(self):
        url = reverse('admin:companies_companygroup_add')
        response = self.client.post(
            url,
            {
                'company': self.company.pk,
                'display_name': 'Posted Scim',
                'source': CompanyGroup.SOURCE_SCIM,
            },
        )
        self.assertEqual(response.status_code, 302, response.content)
        group = CompanyGroup.objects.get(company=self.company, display_name='Posted Scim')
        self.assertEqual(group.source, CompanyGroup.SOURCE_MANUAL)

    def test_model_rejects_manual_to_scim_without_scim_path(self):
        group = CompanyGroup.objects.create(company=self.company, display_name='Manual')
        group.source = CompanyGroup.SOURCE_SCIM
        with self.assertRaisesMessage(
            ValueError,
            'Company group source scim may only be set via SCIM provisioning.',
        ):
            group.save()

    def test_model_rejects_scim_create_without_scim_path(self):
        group = CompanyGroup(
            company=self.company,
            display_name='Bad',
            source=CompanyGroup.SOURCE_SCIM,
        )
        with self.assertRaisesMessage(
            ValueError,
            'Company group source scim may only be set via SCIM provisioning.',
        ):
            group.save()

    def test_scim_provisioned_helper_sets_scim_source(self):
        group = CompanyGroup.create_scim_provisioned(
            company=self.company,
            display_name='IdP',
        )
        self.assertEqual(group.source, CompanyGroup.SOURCE_SCIM)

    def test_admin_create_emits_group_created_action(self):
        ActionRule.objects.create(
            company=self.company,
            name='Groups',
            event_type='identity.group.created',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        url = reverse('admin:companies_companygroup_add')
        with self.captureOnCommitCallbacks(execute=False):
            response = self.client.post(
                url,
                {
                    'company': self.company.pk,
                    'display_name': 'Ops Team',
                },
            )
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(ActionOutbox.objects.filter(event_type='identity.group.created').count(), 1)

    def test_admin_delete_emits_group_deleted_action(self):
        ActionRule.objects.create(
            company=self.company,
            name='Groups',
            event_type='identity.group.deleted',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        group = CompanyGroup.objects.create(company=self.company, display_name='Gone')
        url = reverse('admin:companies_companygroup_delete', args=[group.pk])
        with self.captureOnCommitCallbacks(execute=False):
            response = self.client.post(url, {'post': 'yes'})
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(ActionOutbox.objects.filter(event_type='identity.group.deleted').count(), 1)

    def test_admin_member_edit_logs_membership_changed(self):
        ada = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        group = CompanyGroup.objects.create(company=self.company, display_name='Eng')
        url = reverse('admin:companies_companygroup_change', args=[group.pk])
        response = self.client.post(
            url,
            {'company': self.company.pk, 'display_name': 'Eng', 'members': [ada.pk]},
        )
        self.assertEqual(response.status_code, 302, response.content)
        row = EventLog.objects.get(event_type='identity.group.membership_changed')
        self.assertEqual(row.user_id, ada.pk)
        self.assertEqual(row.data['change'], 'members_added')

        self.client.post(url, {'company': self.company.pk, 'display_name': 'Eng'})
        self.assertEqual(
            list(
                EventLog.objects.filter(event_type='identity.group.membership_changed')
                .order_by('pk')
                .values_list('data__change', flat=True)
            ),
            ['members_added', 'members_removed'],
        )

    def test_admin_bulk_delete_logs_group_deleted(self):
        groups = [CompanyGroup.objects.create(company=self.company, display_name=n) for n in ('A', 'B')]
        response = self.client.post(
            reverse('admin:companies_companygroup_changelist'),
            {'action': 'delete_selected', '_selected_action': [g.pk for g in groups], 'post': 'yes'},
        )
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(EventLog.objects.filter(event_type='identity.group.deleted').count(), 2)
