from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.authapi.models import UserActivity, UserPreference
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyGroup, CompanyMembership

User = get_user_model()


@override_settings(ALLOWED_HOSTS=['testserver'], AUTH_RATE_LIMIT_ENABLED=False)
class UserAudienceTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Audience Co', slug='audience-co')
        self.other = Company.objects.create(name='Other Co', slug='other-co')
        self.owner = self._user('owner', enabled=True)
        self.company.owners.add(self.owner)
        self.anna = self._user('anna', language='fr', first_name='Anna')
        self.bob = self._user('bob')
        self.carl = self._user('carl', enabled=False)
        self.staff = self._user('staff', is_staff=True)
        self.outsider = User.objects.create_user(username='out', email='out@x.com', password='x')
        set_company_access(self.other, self.outsider, enabled=True)
        self.client.force_authenticate(user=self.owner)

    def _user(self, name, *, enabled=True, language=None, is_staff=False, first_name=''):
        user = User.objects.create_user(
            username=name, email=f'{name}@aud.com', password='x', is_staff=is_staff, first_name=first_name
        )
        set_company_access(self.company, user, enabled=enabled)
        if language:
            UserPreference.objects.create(user=user, language=language)
        return user

    def _get(self, **params):
        params.setdefault('company_id', self.company.pk)
        return self.client.get('/api/v1/users/audience', params)

    def _emails(self, response):
        self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
        return [row['email'] for row in response.data['results']]

    def test_enabled_members_with_language_by_default(self):
        response = self._get()
        self.assertEqual(
            self._emails(response), ['owner@aud.com', 'anna@aud.com', 'bob@aud.com', 'staff@aud.com']
        )
        anna = next(row for row in response.data['results'] if row['email'] == 'anna@aud.com')
        self.assertEqual(anna, {'id': self.anna.pk, 'email': 'anna@aud.com', 'first_name': 'Anna', 'last_name': '', 'language': 'fr'})
        self.assertEqual(response.data['results'][0]['language'], 'en')
        self.assertEqual(self._get(count_only='1').data, {'count': 4})

    def test_access_and_roles(self):
        self.assertEqual(self._emails(self._get(access='disabled')), ['carl@aud.com'])
        self.assertEqual(len(self._emails(self._get(access='any'))), 5)
        self.assertEqual(self._emails(self._get(roles='owner')), ['owner@aud.com'])
        self.assertEqual(self._emails(self._get(roles='staff')), ['staff@aud.com'])
        self.assertEqual(self._emails(self._get(roles='member')), ['anna@aud.com', 'bob@aud.com'])

    def test_nested_groups(self):
        team = CompanyGroup.objects.create(company=self.company, display_name='Team')
        sub = CompanyGroup.objects.create(company=self.company, display_name='Sub')
        team.member_groups.add(sub)
        team.members.add(self.anna)
        sub.members.add(self.bob)
        self.assertEqual(self._emails(self._get(group_ids=str(team.pk))), ['anna@aud.com', 'bob@aud.com'])
        self.assertEqual(self._emails(self._get(group_ids=str(sub.pk))), ['bob@aud.com'])

    def test_joined_and_seen(self):
        old = timezone.now() - timedelta(days=90)
        CompanyMembership.objects.filter(company=self.company, user=self.anna).update(created_at=old)
        UserActivity.objects.create(user=self.bob, last_seen_at=timezone.now())
        UserActivity.objects.create(user=self.anna, last_seen_at=old)
        cutoff = (timezone.now() - timedelta(days=30)).date().isoformat()
        self.assertEqual(self._emails(self._get(joined_before=cutoff)), ['anna@aud.com'])
        self.assertNotIn('anna@aud.com', self._emails(self._get(joined_after=cutoff)))
        self.assertEqual(self._emails(self._get(seen_after=cutoff)), ['bob@aud.com'])
        self.assertEqual(
            self._emails(self._get(seen_before=cutoff)), ['owner@aud.com', 'anna@aud.com', 'staff@aud.com']
        )

    def test_hand_picked_users(self):
        self.assertEqual(self._emails(self._get(user_ids=f'{self.bob.pk},{self.outsider.pk}')), ['bob@aud.com'])
        self.assertEqual(
            self._emails(self._get(roles='owner', user_ids=str(self.bob.pk))), ['owner@aud.com', 'bob@aud.com']
        )

    def test_invalid_filter_and_permissions(self):
        response = self._get(roles='admin')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, {'error': 'invalid_filter', 'field': 'roles'})
        self.assertEqual(self._get(seen_after='yesterday').data['field'], 'seen_after')
        self.client.force_authenticate(user=self.bob)
        self.assertEqual(self._get().status_code, 403)
