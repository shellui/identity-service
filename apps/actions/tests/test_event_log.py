from datetime import timedelta
from io import StringIO
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.actions.emit import emit_event
from apps.actions.models import ActionOutbox, ActionRule, EventLog
from apps.actions.registry import all_event_types
from apps.actions.retention import purge_expired_data, retention_status
from apps.authapi.login_audit import LoginOutcome, record_login_event
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyGroup

User = get_user_model()


def _log(company, event_type='identity.user.created', *, days_ago=0.0, user=None, data=None):
    return EventLog.objects.create(
        company=company,
        user=user,
        event_type=event_type,
        data=data or {},
        created_at=timezone.now() - timedelta(days=days_ago),
    )


class RecordEventTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme')
        self.user = User.objects.create_user(username='ada', email='ada@acme.test', password='x')

    def test_emit_records_event_without_webhook_rule(self):
        emit_event(
            'identity.user.created',
            self.company,
            {'user_id': self.user.pk, 'email': 'ada@acme.test', 'username': None, 'source': 'oauth'},
        )
        row = EventLog.objects.get()
        self.assertEqual(row.event_type, 'identity.user.created')
        self.assertEqual(row.company, self.company)
        self.assertEqual(row.user_id, self.user.pk)
        self.assertEqual(row.data, {'email': 'ada@acme.test', 'source': 'oauth'})
        self.assertEqual(ActionOutbox.objects.count(), 0)

    def test_sensitive_fields_are_never_logged(self):
        emit_event(
            'identity.auth.magic_link.requested',
            self.company,
            {'email': 'ada@acme.test', 'magic_link_url': 'https://auth.test/verify?token=secret'},
        )
        self.assertNotIn('magic_link_url', EventLog.objects.get().data)

    def test_events_not_emitted_by_default_are_not_logged(self):
        emit_event('identity.user.updated', self.company, {'user_id': self.user.pk})
        self.assertFalse(EventLog.objects.exists())

    def test_login_is_logged_with_compact_data(self):
        request = RequestFactory().get('/', HTTP_USER_AGENT='UA', REMOTE_ADDR='203.0.113.9')
        record_login_event(
            request=request,
            outcome=LoginOutcome.FAILURE,
            provider='GitHub',
            user=self.user,
            company=self.company,
            failure_reason='Company access is disabled.',
        )
        row = EventLog.objects.get()
        self.assertEqual(row.event_type, 'identity.auth.login.failed')
        self.assertEqual(row.user_id, self.user.pk)
        self.assertEqual(row.data['provider'], 'github')
        self.assertEqual(row.data['failure_reason'], 'Company access is disabled.')
        self.assertEqual(len(row.data['ip_hash']), 64)
        self.assertNotIn('is_staff_at_event', row.data)
        self.assertNotIn('client_city', row.data)

    def test_deleting_user_detaches_events(self):
        row = _log(self.company, user=self.user)
        self.user.delete()
        row.refresh_from_db()
        self.assertIsNone(row.user_id)


@override_settings(ALLOWED_HOSTS=['testserver'])
class EventLogApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme')
        self.other = Company.objects.create(name='Other', slug='other')
        self.owner = User.objects.create_user(username='owner', email='owner@acme.test', password='x')
        self.ada = User.objects.create_user(username='ada', email='ada@acme.test', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.client.force_authenticate(user=self.owner)

    def _get(self, path, **params):
        return self.client.get(path, {'company_id': self.company.id, **params})

    def test_list_newest_first_and_company_scoped(self):
        old = _log(self.company, days_ago=2)
        new = _log(self.company, 'identity.group.created', data={'display_name': 'Eng'})
        _log(self.other)
        response = self._get('/api/v1/events')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 2)
        self.assertEqual([r['id'] for r in response.data['results']], [new.pk, old.pk])
        self.assertEqual(response.data['results'][0]['label'], 'Group created')

    def test_filters(self):
        mine = _log(self.company, 'identity.auth.login.succeeded', user=self.ada, days_ago=1)
        _log(self.company, 'identity.group.created')
        invited = _log(self.company, 'identity.user.invited', data={'email': 'ada@acme.test'})
        old = _log(self.company, days_ago=5)

        def ids(**params):
            return [r['id'] for r in self._get('/api/v1/events', **params).data['results']]

        self.assertEqual(ids(user_id=self.ada.pk), [mine.pk])
        self.assertEqual(ids(user='ADA@acme'), [invited.pk, mine.pk])
        self.assertEqual(ids(event_type='identity.auth.login.succeeded,identity.user.invited'), [invited.pk, mine.pk])
        before = (timezone.now() - timedelta(days=3)).isoformat()
        self.assertEqual(ids(created_before=before), [old.pk])
        self.assertEqual(self._get('/api/v1/events', event_type='nope').status_code, 400)

    def test_user_email_comes_from_user_row(self):
        _log(self.company, user=self.ada)
        row = self._get('/api/v1/events').data['results'][0]
        self.assertEqual(row['user_email'], 'ada@acme.test')

    def test_detail_is_company_scoped(self):
        mine = _log(self.company)
        theirs = _log(self.other)
        self.assertEqual(self._get(f'/api/v1/events/{mine.pk}').status_code, 200)
        self.assertEqual(self._get(f'/api/v1/events/{theirs.pk}').status_code, 404)

    def test_types_include_log_only_events(self):
        rows = {r['type']: r for r in self._get('/api/v1/events/types').data['results']}
        self.assertFalse(rows['identity.auth.login.failed']['webhook'])
        self.assertTrue(rows['identity.user.created']['webhook'])
        self.assertNotIn('identity.user.updated', rows)

    def test_retention_status_flags_stale_events(self):
        _log(self.company, days_ago=7.5)
        self.assertFalse(self._get('/api/v1/events/retention').data['stale_events'])
        _log(self.company, days_ago=8.5)
        data = self._get('/api/v1/events/retention').data
        self.assertTrue(data['stale_events'])
        self.assertEqual(data['data_retention_days'], 7)

    def test_non_owner_is_forbidden(self):
        set_company_access(self.company, self.ada, enabled=True)
        self.client.force_authenticate(user=self.ada)
        self.assertEqual(self._get('/api/v1/events').status_code, 403)

    def test_legacy_login_events_shape(self):
        _log(self.company, 'identity.group.created')
        _log(
            self.company,
            'identity.auth.login.failed',
            user=self.ada,
            data={'provider': 'github', 'failure_reason': 'nope', 'client_country': 'FR'},
        )
        response = self._get('/api/v1/login-events', outcome='failure', client_country='fr')
        self.assertEqual(response.data['count'], 1)
        row = response.data['results'][0]
        self.assertEqual(row['outcome'], 'failure')
        self.assertEqual(row['provider'], 'github')
        self.assertEqual(row['user_email'], 'ada@acme.test')
        self.assertFalse(row['is_staff_at_event'])
        self.assertEqual(row['client_city'], '')

    def test_login_events_cannot_be_webhook_rules(self):
        response = self.client.post(
            f'/api/v1/actions/rules?company_id={self.company.id}',
            {'name': 'x', 'event_type': 'identity.auth.login.failed', 'url': 'https://hooks.example.com/x'},
            format='json',
        )
        self.assertEqual(response.status_code, 400)
        catalog = self._get('/api/v1/actions/events').data['results']
        self.assertNotIn('identity.auth.login.failed', {r['type'] for r in catalog})

    def test_company_api_exposes_retention_read_only(self):
        url = f'/api/v1/companies/{self.company.id}/'
        self.assertEqual(self.client.get(url).data['data_retention_days'], 7)
        self.client.patch(url, {'data_retention_days': 90}, format='json')
        self.company.refresh_from_db()
        self.assertEqual(self.company.data_retention_days, 7)


@override_settings(ALLOWED_HOSTS=['testserver'], AUTH_RATE_LIMIT_ENABLED=False)
class AdminApiEventLoggingTests(TestCase):
    """Every write the admin app makes must land in the event log, with or without webhook rules."""

    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme')
        self.owner = User.objects.create_user(username='owner', email='owner@acme.test', password='x')
        self.ada = User.objects.create_user(username='ada', email='ada@acme.test', password='x')
        set_company_access(self.company, self.owner, enabled=True)
        set_company_access(self.company, self.ada, enabled=True)
        self.company.owners.add(self.owner)
        self.client.force_authenticate(user=self.owner)

    def _url(self, path):
        return f'{path}?company_id={self.company.id}'

    def _types(self):
        return list(EventLog.objects.order_by('pk').values_list('event_type', flat=True))

    def test_group_create_rename_delete(self):
        created = self.client.post(self._url('/api/v1/groups'), {'display_name': 'Eng'}, format='json')
        self.assertEqual(created.status_code, 201, created.data)
        url = self._url(f"/api/v1/groups/{created.data['id']}")
        self.client.put(url, {'display_name': 'Engineering'}, format='json')
        self.client.put(url, {'display_name': 'Engineering'}, format='json')
        self.client.delete(url)
        self.assertEqual(
            self._types(),
            ['identity.group.created', 'identity.group.updated', 'identity.group.deleted'],
        )
        self.assertEqual(EventLog.objects.get(event_type='identity.group.updated').data['display_name'], 'Engineering')

    def test_user_group_membership_changes(self):
        eng = CompanyGroup.objects.create(company=self.company, display_name='Eng')
        ops = CompanyGroup.objects.create(company=self.company, display_name='Ops')
        url = self._url(f'/api/v1/users/{self.ada.pk}')
        self.client.put(url, {'group_ids': [eng.pk]}, format='json')
        self.client.put(url, {'group_ids': [eng.pk]}, format='json')
        self.client.put(url, {'group_ids': [ops.pk]}, format='json')
        rows = list(EventLog.objects.order_by('pk').values_list('data__display_name', 'data__change', 'user_id'))
        self.assertEqual(
            rows,
            [
                ('Eng', 'members_added', self.ada.pk),
                ('Eng', 'members_removed', self.ada.pk),
                ('Ops', 'members_added', self.ada.pk),
            ],
        )

    def test_invitation_and_revoke(self):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                self._url('/api/v1/invitations'),
                {'email': 'grace@acme.test', 'language': 'en'},
                format='json',
            )
        self.assertEqual(response.status_code, 201, response.data)
        self.client.post(self._url(f"/api/v1/invitations/{response.data['invitation']['id']}/revoke"))
        self.assertEqual(self._types(), ['identity.user.invited', 'identity.user.invitation_revoked'])

    def test_scim_token_create_and_revoke(self):
        created = self.client.post(self._url('/api/v1/scim/tokens'), {'name': 'IdP'}, format='json')
        self.assertEqual(created.status_code, 201, created.data)
        self.client.post(self._url(f"/api/v1/scim/tokens/{created.data['id']}/revoke"))
        self.assertEqual(self._types(), ['identity.scim.token.created', 'identity.scim.token.revoked'])

    def test_user_delete(self):
        response = self.client.delete(self._url(f'/api/v1/users/{self.ada.pk}'))
        self.assertEqual(response.status_code, 204)
        row = EventLog.objects.get()
        self.assertEqual(row.event_type, 'identity.user.deleted')
        self.assertEqual(row.data['email'], 'ada@acme.test')


class EventEmitterCoverageTests(TestCase):
    def test_every_logged_event_type_has_an_emitter(self):
        """A registered type nothing emits never shows up in the log; catch it here."""
        apps_dir = Path(__file__).resolve().parents[2]
        source = '\n'.join(
            p.read_text()
            for p in apps_dir.rglob('*.py')
            if 'tests' not in p.parts and 'migrations' not in p.parts and p.name != 'identity_events.py'
        )
        missing = [
            e.id for e in all_event_types() if e.emit_by_default and f"'{e.id}'" not in source
        ]
        self.assertEqual(missing, [])


class PurgeExpiredDataTests(TestCase):
    def setUp(self):
        self.short = Company.objects.create(name='Short', slug='short', data_retention_days=1)
        self.long = Company.objects.create(name='Long', slug='long', data_retention_days=30)
        rule = ActionRule.objects.create(
            company=self.short,
            name='Hook',
            event_type='identity.user.created',
            config={'url': 'https://example.com/hook'},
        )
        self.old = timezone.now() - timedelta(days=3)
        self.done = ActionOutbox.objects.create(
            company=self.short, action_rule=rule, event_type='x', envelope={}, status=ActionOutbox.STATUS_DELIVERED
        )
        self.pending = ActionOutbox.objects.create(
            company=self.short, action_rule=rule, event_type='x', envelope={}, status=ActionOutbox.STATUS_PENDING
        )
        ActionOutbox.objects.update(created_at=self.old)

    def test_purge_uses_each_company_retention(self):
        expired = _log(self.short, days_ago=2)
        kept_recent = _log(self.short, days_ago=0.5)
        kept_long = _log(self.long, days_ago=2)
        orphan_expired = _log(None, days_ago=8)
        orphan_kept = _log(None, days_ago=6)

        stats = purge_expired_data(batch_size=1)

        self.assertEqual(stats['events'], 2)
        self.assertEqual(stats['webhook_deliveries'], 1)
        self.assertTrue(stats['complete'])
        remaining = set(EventLog.objects.values_list('pk', flat=True))
        self.assertEqual(remaining, {kept_recent.pk, kept_long.pk, orphan_kept.pk})
        self.assertNotIn(expired.pk, remaining)
        self.assertNotIn(orphan_expired.pk, remaining)
        self.assertEqual(list(ActionOutbox.objects.values_list('pk', flat=True)), [self.pending.pk])
        self.assertFalse(retention_status(self.short)['stale_events'])

    def test_dry_run_deletes_nothing(self):
        _log(self.short, days_ago=2)
        stats = purge_expired_data(dry_run=True)
        self.assertEqual(stats['events'], 1)
        self.assertEqual(EventLog.objects.count(), 1)

    def test_command_output(self):
        _log(self.short, days_ago=2)
        out = StringIO()
        call_command('purge_expired_data', stdout=out)
        self.assertIn('deleted events=1 webhook_deliveries=1', out.getvalue())
        self.assertIn('complete=true', out.getvalue())
        self.assertEqual(EventLog.objects.count(), 0)
