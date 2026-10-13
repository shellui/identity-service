from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.models import ActionOutbox, ActionRule, EventLog
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyGroup

User = get_user_model()


@override_settings(ALLOWED_HOSTS=['testserver'])
class UserUpdatedEventTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme')
        self.owner = User.objects.create_user(username='owner', email='owner@acme.test', password='x')
        self.ada = User.objects.create_user(username='ada', email='ada@acme.test', password='x', first_name='Ada')
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.ada, enabled=True)
        self.company.owners.add(self.owner)
        owner_tokens = _issue_shellui_tokens(self.owner, company=self.company)
        ada_tokens = _issue_shellui_tokens(self.ada, company=self.company)
        self.owner_auth = f'Bearer {owner_tokens["access_token"]}'
        self.ada_auth = f'Bearer {ada_tokens["access_token"]}'

    def _updated(self):
        return list(EventLog.objects.filter(event_type='identity.user.updated').order_by('pk'))

    def test_name_change_emits_once_and_repeat_is_quiet(self):
        response = self.client.patch(
            '/api/v1/user',
            {'name': 'Ada Lovelace'},
            format='json',
            HTTP_AUTHORIZATION=self.ada_auth,
        )
        self.assertEqual(response.status_code, 200, response.data)
        row = EventLog.objects.get(event_type='identity.user.updated')
        self.assertEqual(row.user_id, self.ada.pk)
        self.assertEqual(row.data['source'], 'rest')
        self.assertEqual(row.data['changed_fields'], ['name'])
        self.assertEqual(row.data['name'], 'Ada Lovelace')
        self.assertNotIn('token', row.data)
        self.assertNotIn('magic_link_url', row.data)

        again = self.client.patch(
            '/api/v1/user',
            {'name': 'Ada Lovelace'},
            format='json',
            HTTP_AUTHORIZATION=self.ada_auth,
        )
        self.assertEqual(again.status_code, 200)
        self.assertEqual(len(self._updated()), 1)

    def test_language_change_emits_and_theme_only_does_not(self):
        theme = self.client.put(
            '/api/v1/preferences',
            {'themeName': 'dark'},
            format='json',
            HTTP_AUTHORIZATION=self.ada_auth,
        )
        self.assertEqual(theme.status_code, 200, theme.data)
        self.assertEqual(self._updated(), [])

        language = self.client.put(
            '/api/v1/preferences',
            {'language': 'fr'},
            format='json',
            HTTP_AUTHORIZATION=self.ada_auth,
        )
        self.assertEqual(language.status_code, 200, language.data)
        row = EventLog.objects.get(event_type='identity.user.updated')
        self.assertEqual(row.data['changed_fields'], ['language'])
        self.assertEqual(row.data['language'], 'fr')

    def test_admin_access_and_groups(self):
        group = CompanyGroup.objects.create(company=self.company, display_name='Eng')
        url = f'/api/v1/users/{self.ada.pk}?company_id={self.company.id}'
        response = self.client.put(
            url,
            {'is_active': False, 'group_ids': [group.pk]},
            format='json',
            HTTP_AUTHORIZATION=self.owner_auth,
        )
        self.assertEqual(response.status_code, 200, response.data)
        row = EventLog.objects.get(event_type='identity.user.updated')
        self.assertEqual(row.data['source'], 'admin')
        self.assertEqual(row.data['changed_fields'], ['active', 'groups'])
        self.assertEqual(row.data['group_ids'], [group.pk])
        self.assertEqual(row.data['role'], 'member')
        self.assertTrue(
            EventLog.objects.filter(event_type='identity.group.membership_changed').exists()
        )
        self.assertFalse(row.data.get('active', False))

    def test_owner_change_emits_role(self):
        response = self.client.patch(
            f'/api/v1/companies/{self.company.pk}/',
            {'owner_ids': [self.owner.pk, self.ada.pk]},
            format='json',
            HTTP_AUTHORIZATION=self.owner_auth,
        )
        self.assertEqual(response.status_code, 200, response.data)
        row = EventLog.objects.get(event_type='identity.user.updated')
        self.assertEqual(row.user_id, self.ada.pk)
        self.assertEqual(row.data['changed_fields'], ['role'])
        self.assertEqual(row.data['role'], 'owner')

    def test_webhook_rule_gets_the_event_without_secrets(self):
        ActionRule.objects.create(
            company=self.company,
            name='Updated',
            event_type='identity.user.updated',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/hook', 'secret': 'whsec_test'},
        )
        self.client.patch(
            '/api/v1/user',
            {'name': 'Ada Lovelace', 'token': 'secret-token', 'magic_link_url': 'https://auth.example/x'},
            format='json',
            HTTP_AUTHORIZATION=self.ada_auth,
        )
        row = ActionOutbox.objects.get(event_type='identity.user.updated')
        data = row.envelope['data']
        self.assertEqual(data['changed_fields'], ['name'])
        self.assertNotIn('token', data)
        self.assertNotIn('magic_link_url', data)
        self.assertNotIn('secret', data)
