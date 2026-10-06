"""Scheduled job monitoring: run recording, health, metrics, staff API and correlation ids."""

from datetime import timedelta
from io import StringIO
from unittest import mock

import redis
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import OperationalError
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.actions import tasks
from apps.actions.delivery import deliver_outbox_row, retry_pending_webhooks
from apps.actions.email_events import retry_pending_email_events
from apps.actions.models import (
    ActionOutbox,
    ActionRule,
    DeliveryAttempt,
    EmailEventOutbox,
    EventLog,
    ScheduledJobCounter,
    ScheduledJobRun,
    ScheduledJobState,
)
from apps.actions.registry import get_event_type, is_webhook_event, webhook_event_types
from apps.actions.retention import purge_expired_data
from apps.actions.scheduled_jobs import (
    PURGE_EXPIRED_DATA,
    RETRY_WEBHOOKS,
    compute_health,
    is_overdue,
    jobs_overview,
    sanitize_error_message,
)
from apps.actions.tests.test_scheduled_tasks import FakeRedis
from apps.actions.webhook_transport import WebhookPostResult
from apps.companies.access import set_company_access
from apps.companies.models import Company
from config.request_context import request_id_var
from config.task_lock import beat_heartbeat_key, lock_key

User = get_user_model()

_EMPTY_STATS = {'processed': 0, 'delivered': 0, 'retried': 0, 'dead': 0}
_SECRET_ERROR = (
    'connect failed https://hooks.example.com/h?token=abc123secret&code=xyz '
    'redis://user:hunter2@redis:6379/0 Authorization: Bearer abcdefghijklmnop password=hunter2'
)


def _counter(job, name):
    row = ScheduledJobCounter.objects.filter(job=job, name=name).first()
    return row.value if row else 0


class FakeRedisWithGet(FakeRedis):
    def get(self, key):
        self._expire()
        item = self.store.get(key)
        return item[0].encode() if item else None

    def ping(self):
        return True


class RunRecordingTests(TestCase):
    def setUp(self):
        self.fake = FakeRedisWithGet()
        patcher = mock.patch('config.task_lock.get_lock_client', return_value=self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    @mock.patch('apps.actions.management.commands.retry_webhooks.retry_pending_email_events')
    @mock.patch('apps.actions.management.commands.retry_webhooks.retry_pending_webhooks')
    def test_command_path_records_a_run(self, retry, retry_email):
        retry.return_value = {'processed': 3, 'delivered': 1, 'retried': 1, 'dead': 1}
        retry_email.return_value = {'processed': 1, 'delivered': 1, 'retried': 0, 'dead': 0}
        out = StringIO()

        call_command('retry_webhooks', stdout=out)

        run = ScheduledJobRun.objects.get()
        self.assertEqual(run.job, 'retry_webhooks')
        self.assertEqual(run.trigger, 'command')
        self.assertEqual(run.status, 'succeeded')
        self.assertIsNotNone(run.finished_at)
        self.assertIsNotNone(run.duration_ms)
        self.assertTrue(run.host)
        self.assertEqual(
            run.counts,
            {
                'webhook_deliveries_attempted': 3,
                'webhook_deliveries_succeeded': 1,
                'webhook_deliveries_failed': 1,
                'webhook_deliveries_given_up': 1,
                'email_events_attempted': 1,
                'email_events_succeeded': 1,
                'email_events_failed': 0,
                'email_events_given_up': 0,
            },
        )
        self.assertEqual(retry.call_args.kwargs['scheduled_job_run_id'], run.pk)
        self.assertEqual(retry_email.call_args.kwargs['scheduled_job_run_id'], run.pk)
        self.assertIn(f'run_id={run.pk}', out.getvalue())

        state = ScheduledJobState.objects.get(job='retry_webhooks')
        self.assertEqual(state.last_success_at, run.finished_at)
        self.assertEqual(state.last_started_at, run.started_at)
        self.assertEqual(_counter('retry_webhooks', 'runs.succeeded'), 1)
        self.assertEqual(_counter('retry_webhooks', 'items.webhook_deliveries_attempted'), 3)
        self.assertEqual(_counter('retry_webhooks', 'items.email_events_failed'), 0)

        event = EventLog.objects.get(pk=run.event_log_id)
        self.assertIsNone(event.company_id)
        self.assertEqual(event.event_type, 'identity.scheduled_job.succeeded')
        self.assertEqual(event.data['run_id'], run.pk)
        self.assertEqual(event.data['trigger'], 'command')

    @mock.patch('apps.actions.management.commands.purge_expired_data.purge_expired_data')
    def test_celery_path_records_a_run(self, purge):
        purge.return_value = {
            'events': 2,
            'webhook_deliveries': 1,
            'email_events': 0,
            'scim_provisioning_events': 0,
            'scheduled_job_runs': 4,
            'complete': True,
        }
        self.assertIn('deleted events=2', tasks.purge_expired_data.apply().get())

        run = ScheduledJobRun.objects.get()
        self.assertEqual((run.job, run.trigger, run.status), ('purge_expired_data', 'celery', 'succeeded'))
        self.assertEqual(run.counts['events'], 2)
        self.assertEqual(run.counts['scheduled_job_runs'], 4)
        self.assertIs(run.counts['complete'], True)
        self.assertEqual(_counter('purge_expired_data', 'items.events'), 2)
        self.assertEqual(_counter('purge_expired_data', 'items.complete'), 0)

    def test_dry_run_is_not_recorded(self):
        call_command('retry_webhooks', dry_run=True, stdout=StringIO())
        call_command('purge_expired_data', dry_run=True, stdout=StringIO())
        self.assertFalse(ScheduledJobRun.objects.exists())

    @mock.patch('apps.actions.tasks.call_command')
    def test_skipped_locked_counts_without_a_row(self, call):
        self.fake.set(lock_key('retry_webhooks'), 'other-worker', ex=60)
        self.assertEqual(tasks.retry_webhooks.apply().get(), 'skipped')
        call.assert_not_called()
        self.assertFalse(ScheduledJobRun.objects.exists())
        self.assertEqual(_counter('retry_webhooks', 'runs.skipped_locked'), 1)
        self.assertIsNotNone(ScheduledJobState.objects.get(job='retry_webhooks').last_skipped_at)

    @mock.patch('apps.actions.management.commands.retry_webhooks.retry_pending_webhooks')
    def test_failure_is_recorded_logged_and_sanitized(self, retry):
        retry.side_effect = OperationalError(_SECRET_ERROR)

        with self.assertLogs('apps.actions.scheduled_jobs', level='ERROR') as logs:
            with self.assertRaises(CommandError) as ctx:
                call_command('retry_webhooks', stdout=StringIO())

        run = ScheduledJobRun.objects.get()
        self.assertEqual(run.status, 'failed')
        self.assertEqual(run.error_key, 'database_error')
        self.assertEqual(run.error_class, 'OperationalError')
        for secret in ('abc123secret', 'xyz', 'hunter2', 'abcdefghijklmnop', '?token'):
            self.assertNotIn(secret, run.error_message)
            self.assertNotIn(secret, str(ctx.exception))
            self.assertNotIn(secret, logs.output[0])
        self.assertIn('https://hooks.example.com/h', run.error_message)
        self.assertIn(f'run_id={run.pk}', logs.output[0])
        self.assertIn(f'run_id={run.pk}', str(ctx.exception))
        self.assertNotIn('hunter2', ''.join(logs.output))
        self.assertEqual(request_id_var.get(), '-', 'request id is restored after the run')

        self.assertEqual(_counter('retry_webhooks', 'runs.failed'), 1)
        state = ScheduledJobState.objects.get(job='retry_webhooks')
        self.assertIsNotNone(state.last_failure_at)
        self.assertIsNone(state.last_success_at)
        event = EventLog.objects.get(pk=run.event_log_id)
        self.assertEqual(event.event_type, 'identity.scheduled_job.failed')
        self.assertIsNone(event.company_id)
        self.assertEqual(event.data['error_key'], 'database_error')
        self.assertNotIn('error_message', event.data)

    @mock.patch('apps.actions.management.commands.retry_webhooks.retry_pending_webhooks')
    def test_celery_failure_returns_failed_without_raising(self, retry):
        retry.side_effect = RuntimeError('boom')
        with self.assertLogs('apps.actions.scheduled_jobs', level='ERROR'):
            self.assertEqual(tasks.retry_webhooks.apply().get(), 'failed')
        run = ScheduledJobRun.objects.get()
        self.assertEqual((run.trigger, run.status, run.error_key), ('celery', 'failed', 'unexpected_error'))
        self.assertEqual(self.fake.store, {}, 'lock released after a failed run')

    def test_redis_down_on_lock_records_a_failed_run(self):
        client = mock.Mock()
        client.set.side_effect = redis.ConnectionError('Error 111 connecting to redis:6379')
        with mock.patch('config.task_lock.get_lock_client', return_value=client):
            with self.assertLogs('apps.actions.scheduled_jobs', level='ERROR'):
                self.assertEqual(tasks.retry_webhooks.apply().get(), 'failed')
        run = ScheduledJobRun.objects.get()
        self.assertEqual((run.trigger, run.status, run.error_key), ('celery', 'failed', 'redis_error'))

    @mock.patch('apps.actions.management.commands.retry_webhooks.retry_pending_email_events')
    @mock.patch('apps.actions.management.commands.retry_webhooks.retry_pending_webhooks')
    def test_stale_running_row_is_marked_interrupted(self, retry, retry_email):
        retry.return_value = dict(_EMPTY_STATS)
        retry_email.return_value = dict(_EMPTY_STATS)
        stale = ScheduledJobRun.objects.create(
            job='retry_webhooks',
            trigger='celery',
            started_at=timezone.now() - timedelta(minutes=10),
        )
        recent = ScheduledJobRun.objects.create(
            job='retry_webhooks',
            trigger='command',
            started_at=timezone.now() - timedelta(seconds=30),
        )
        with self.assertLogs('apps.actions.scheduled_jobs', level='WARNING'):
            call_command('retry_webhooks', stdout=StringIO())
        stale.refresh_from_db()
        recent.refresh_from_db()
        self.assertEqual((stale.status, stale.error_key), ('failed', 'interrupted'))
        self.assertEqual(recent.status, 'running')


class SanitizeTests(TestCase):
    def test_sanitize_error_message(self):
        cleaned = sanitize_error_message(_SECRET_ERROR + ' eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.c2lnbmF0dXJl ' + 'a' * 40)
        for secret in ('abc123secret', 'hunter2', 'abcdefghijklmnop', 'eyJhbGci', 'a' * 40):
            self.assertNotIn(secret, cleaned)
        self.assertIn('redis://redis:6379/0', cleaned)
        self.assertLessEqual(len(sanitize_error_message('x' * 1000)), 300)
        self.assertEqual(sanitize_error_message('line one\nline two'), 'line one line two')


class HealthTests(TestCase):
    def _state(self, job, **fields):
        state, _ = ScheduledJobState.objects.get_or_create(job=job)
        for key, value in fields.items():
            setattr(state, key, value)
        state.save()
        return state

    def test_overdue_after_three_intervals(self):
        now = timezone.now()
        retry = self._state('retry_webhooks', last_success_at=now - timedelta(minutes=2))
        self.assertFalse(is_overdue(RETRY_WEBHOOKS, retry, now))
        retry.last_success_at = now - timedelta(minutes=3, seconds=1)
        self.assertTrue(is_overdue(RETRY_WEBHOOKS, retry, now))

        purge = self._state('purge_expired_data', last_success_at=now - timedelta(hours=2))
        self.assertFalse(is_overdue(PURGE_EXPIRED_DATA, purge, now))
        purge.last_success_at = now - timedelta(hours=2, minutes=16)
        self.assertTrue(is_overdue(PURGE_EXPIRED_DATA, purge, now))

    def test_before_the_first_success_the_clock_starts_at_state_creation(self):
        now = timezone.now()
        state = self._state('purge_expired_data', created_at=now - timedelta(minutes=30), last_success_at=None)
        self.assertFalse(is_overdue(PURGE_EXPIRED_DATA, state, now))
        state.created_at = now - timedelta(hours=3)
        self.assertTrue(is_overdue(PURGE_EXPIRED_DATA, state, now))

    def test_health_values(self):
        now = timezone.now()
        state = self._state('retry_webhooks', created_at=now - timedelta(hours=1))
        self.assertEqual(compute_health(RETRY_WEBHOOKS, state, None, now, enabled=False), 'disabled')
        self.assertEqual(compute_health(RETRY_WEBHOOKS, state, None, now, enabled=True), 'overdue')
        state.last_started_at = now
        state.last_success_at = now - timedelta(seconds=30)
        ok = ScheduledJobRun(job='retry_webhooks', trigger='command', status='succeeded')
        failed = ScheduledJobRun(job='retry_webhooks', trigger='command', status='failed')
        self.assertEqual(compute_health(RETRY_WEBHOOKS, state, ok, now, enabled=True), 'healthy')
        # Cron runs keep being monitored when the in-container scheduler is off.
        self.assertEqual(compute_health(RETRY_WEBHOOKS, state, ok, now, enabled=False), 'healthy')
        self.assertEqual(compute_health(RETRY_WEBHOOKS, state, failed, now, enabled=True), 'failing')

    def test_next_run_of_the_hourly_job_is_minute_17(self):
        moment = timezone.now().replace(hour=10, minute=20, second=5, microsecond=0)
        self.assertEqual(PURGE_EXPIRED_DATA.next_after(moment), moment.replace(hour=11, minute=17, second=0))
        self.assertEqual(
            PURGE_EXPIRED_DATA.next_after(moment.replace(minute=5)), moment.replace(minute=17, second=0)
        )
        self.assertEqual(RETRY_WEBHOOKS.next_after(moment), moment + timedelta(seconds=60))

    @override_settings(CELERY_BROKER_URL='redis://broker:6379/0', SCHEDULER_ENABLED=True)
    def test_overview_reports_redis_and_beat(self):
        fake = FakeRedisWithGet()
        with mock.patch('config.task_lock.get_lock_client', return_value=fake):
            stale = jobs_overview()
            from config.celery import _beat_heartbeat

            _beat_heartbeat(sender='actions.retry_webhooks')
            _beat_heartbeat(sender='some.other.task')
            fresh = jobs_overview()
        self.assertTrue(stale['redis_reachable'])
        self.assertTrue(stale['beat_stale'])
        self.assertIsNone(stale['beat_last_seen_at'])
        self.assertIn(beat_heartbeat_key(), fake.store)
        self.assertFalse(fresh['beat_stale'])
        self.assertIsNotNone(fresh['beat_last_seen_at'])

    @override_settings(CELERY_BROKER_URL='redis://broker:6379/0')
    def test_overview_reports_redis_unreachable(self):
        client = mock.Mock()
        client.ping.side_effect = redis.ConnectionError('down')
        client.get.side_effect = redis.ConnectionError('down')
        with mock.patch('config.task_lock.get_lock_client', return_value=client):
            data = jobs_overview()
        self.assertFalse(data['redis_reachable'])
        self.assertIsNone(data['beat_last_seen_at'])

    @override_settings(CELERY_BROKER_URL='')
    def test_overview_without_broker(self):
        data = jobs_overview()
        self.assertIsNone(data['redis_reachable'])
        self.assertEqual([j['job'] for j in data['jobs']], ['retry_webhooks', 'purge_expired_data'])


class RetentionTests(TestCase):
    def test_purge_deletes_runs_older_than_seven_days(self):
        now = timezone.now()
        old = ScheduledJobRun.objects.create(job='retry_webhooks', trigger='celery', status='succeeded')
        ScheduledJobRun.objects.filter(pk=old.pk).update(started_at=now - timedelta(days=8))
        kept = ScheduledJobRun.objects.create(job='retry_webhooks', trigger='celery', status='succeeded')
        ScheduledJobRun.objects.filter(pk=kept.pk).update(started_at=now - timedelta(days=6))

        self.assertEqual(purge_expired_data(dry_run=True, now=now)['scheduled_job_runs'], 1)
        stats = purge_expired_data(now=now)

        self.assertEqual(stats['scheduled_job_runs'], 1)
        self.assertEqual(list(ScheduledJobRun.objects.values_list('pk', flat=True)), [kept.pk])

    def test_platform_events_expire_with_the_default_retention(self):
        now = timezone.now()
        event = EventLog.objects.create(
            company=None, event_type='identity.scheduled_job.succeeded', data={'run_id': 1}
        )
        EventLog.objects.filter(pk=event.pk).update(created_at=now - timedelta(days=8))
        purge_expired_data(now=now)
        self.assertFalse(EventLog.objects.filter(pk=event.pk).exists())


@override_settings(ALLOWED_HOSTS=['testserver'], CELERY_BROKER_URL='')
class StaffApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme-jobs')
        self.staff = User.objects.create_user(username='staff', email='staff@x.test', password='x', is_staff=True)
        self.owner = User.objects.create_user(username='owner', email='owner@x.test', password='x')
        self.member = User.objects.create_user(username='member', email='member@x.test', password='x')
        for user in (self.staff, self.owner, self.member):
            set_company_access(self.company, user, enabled=True)
        self.company.owners.add(self.owner)
        self.run = ScheduledJobRun.objects.create(
            job='retry_webhooks',
            trigger='celery',
            status='failed',
            finished_at=timezone.now(),
            duration_ms=120,
            counts={'webhook_deliveries_attempted': 1},
            error_key='network_error',
            error_class='ConnectionError',
            error_message='connect failed',
        )

    def _get(self, user, path):
        self.client.force_authenticate(user=user)
        return self.client.get(f'{path}{"&" if "?" in path else "?"}company_id={self.company.id}')

    def test_permissions(self):
        paths = (
            '/api/v1/scheduled-jobs',
            '/api/v1/scheduled-jobs/retry_webhooks/runs',
            f'/api/v1/scheduled-jobs/runs/{self.run.pk}',
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(self._get(self.staff, path).status_code, 200)
                self.assertEqual(self._get(self.owner, path).status_code, 403)
                self.assertEqual(self._get(self.member, path).status_code, 403)
                self.client.force_authenticate(user=None)
                self.assertEqual(self.client.get(path).status_code, 401)

    def test_overview_payload_uses_keys_only(self):
        data = self._get(self.staff, '/api/v1/scheduled-jobs').json()
        self.assertEqual(set(data), {
            'generated_at', 'scheduler_enabled', 'redis_reachable', 'beat_last_seen_at', 'beat_stale', 'jobs',
        })
        retry = next(j for j in data['jobs'] if j['job'] == 'retry_webhooks')
        self.assertEqual(retry['health'], 'failing')
        self.assertEqual(retry['last_run']['id'], self.run.pk)
        self.assertEqual(retry['last_run']['error_key'], 'network_error')
        self.assertEqual(retry['last_24h'], {'succeeded': 0, 'failed': 1})
        self.assertEqual(retry['interval_seconds'], 60)
        self.assertEqual(retry['overdue_after_seconds'], 180)
        self.assertIn('next_expected_at', retry)

    def test_runs_list_limit_and_unknown_job(self):
        for _ in range(3):
            ScheduledJobRun.objects.create(job='retry_webhooks', trigger='command', status='succeeded')
        data = self._get(self.staff, '/api/v1/scheduled-jobs/retry_webhooks/runs?limit=2').json()
        self.assertEqual(len(data['results']), 2)
        failed = self._get(self.staff, '/api/v1/scheduled-jobs/retry_webhooks/runs?status=failed').json()
        self.assertEqual([r['id'] for r in failed['results']], [self.run.pk])
        self.assertEqual(self._get(self.staff, '/api/v1/scheduled-jobs/nope/runs').status_code, 404)
        self.assertEqual(self._get(self.staff, '/api/v1/scheduled-jobs/retry_webhooks/runs?limit=x').status_code, 400)

    def test_run_detail_lists_correlated_deliveries_and_emails(self):
        rule = ActionRule.objects.create(
            company=self.company,
            name='hook',
            event_type='identity.user.created',
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        outbox = ActionOutbox.objects.create(
            company=self.company, action_rule=rule, event_type='identity.user.created', envelope={}
        )
        DeliveryAttempt.objects.create(
            outbox=outbox,
            status='success',
            attempt_number=2,
            trigger='automatic_retry',
            scheduled_job_run_id=self.run.pk,
        )
        DeliveryAttempt.objects.create(outbox=outbox, status='failure', attempt_number=1, trigger='dispatch')
        EmailEventOutbox.objects.create(
            company=self.company,
            event_type='identity.user.created',
            idempotency_key='k1',
            body={},
            last_trigger='automatic_retry',
            last_scheduled_job_run_id=self.run.pk,
        )
        data = self._get(self.staff, f'/api/v1/scheduled-jobs/runs/{self.run.pk}').json()
        self.assertEqual(len(data['webhook_delivery_attempts']), 1)
        self.assertEqual(data['webhook_delivery_attempts'][0]['delivery_id'], str(outbox.pk))
        self.assertEqual(data['webhook_delivery_attempts'][0]['company_id'], self.company.pk)
        self.assertEqual(len(data['email_events']), 1)
        self.assertFalse(data['webhook_delivery_attempts_truncated'])

        # Back from a delivery to the run: staff see the run id, owners only the trigger.
        staff_view = self._get(self.staff, f'/api/v1/actions/deliveries/{outbox.pk}').json()
        retry_attempt = next(a for a in staff_view['attempts'] if a['attempt_number'] == 2)
        self.assertEqual(retry_attempt['scheduled_job_run_id'], self.run.pk)
        self.assertEqual(retry_attempt['trigger'], 'automatic_retry')
        owner_view = self._get(self.owner, f'/api/v1/actions/deliveries/{outbox.pk}').json()
        for attempt in owner_view['attempts']:
            self.assertNotIn('scheduled_job_run_id', attempt)
        self.assertEqual({a['trigger'] for a in owner_view['attempts']}, {'automatic_retry', 'dispatch'})

        listed = self._get(self.staff, f'/api/v1/actions/deliveries?scheduled_job_run_id={self.run.pk}').json()
        self.assertEqual([r['id'] for r in listed['results']], [str(outbox.pk)])
        denied = self._get(self.owner, f'/api/v1/actions/deliveries?scheduled_job_run_id={self.run.pk}')
        self.assertEqual(denied.status_code, 403)

    def test_platform_events_are_staff_only(self):
        EventLog.objects.create(company=None, event_type='identity.scheduled_job.failed', data={'run_id': 1})
        EventLog.objects.create(company=None, event_type='identity.auth.login.failed', data={})

        company_log = self._get(self.staff, '/api/v1/events').json()
        self.assertEqual(company_log['count'], 0)
        platform = self._get(self.staff, '/api/v1/events?scope=platform').json()
        self.assertEqual([r['event_type'] for r in platform['results']], ['identity.scheduled_job.failed'])
        self.assertEqual(self._get(self.owner, '/api/v1/events?scope=platform').status_code, 403)
        self.assertEqual(self._get(self.staff, '/api/v1/events?scope=nope').status_code, 400)

        types = {r['type'] for r in self._get(self.owner, '/api/v1/events/types').json()['results']}
        self.assertNotIn('identity.scheduled_job.succeeded', types)
        self.assertNotIn('identity.scheduled_job.failed', types)


class EventCatalogTests(TestCase):
    def test_job_events_are_not_subscribable(self):
        for event_id in ('identity.scheduled_job.succeeded', 'identity.scheduled_job.failed'):
            event = get_event_type(event_id)
            self.assertTrue(event.staff_only)
            self.assertFalse(event.webhook)
            self.assertFalse(is_webhook_event(event_id))
            self.assertNotIn(event_id, {e.id for e in webhook_event_types()})


@override_settings(ALLOWED_HOSTS=['testserver'], CELERY_BROKER_URL='')
class MetricsTests(TestCase):
    @mock.patch('apps.actions.management.commands.retry_webhooks.retry_pending_email_events')
    @mock.patch('apps.actions.management.commands.retry_webhooks.retry_pending_webhooks')
    def test_global_metrics_include_scheduled_jobs(self, retry, retry_email):
        retry.return_value = {'processed': 2, 'delivered': 2, 'retried': 0, 'dead': 0}
        retry_email.return_value = dict(_EMPTY_STATS)
        call_command('retry_webhooks', stdout=StringIO())
        staff = User.objects.create_user(username='staff', email='s@x.test', password='x', is_staff=True)
        client = APIClient()
        client.force_authenticate(user=staff)

        body = client.get('/api/v1/metrics/all').content.decode()

        self.assertIn('shellui_auth_scheduled_job_runs_total{job="retry_webhooks",status="succeeded"} 1.0', body)
        self.assertIn('shellui_auth_scheduled_job_runs_total{job="purge_expired_data",status="failed"} 0.0', body)
        self.assertIn(
            'shellui_auth_scheduled_job_items_total{job="retry_webhooks",kind="webhook_deliveries_succeeded"} 2.0',
            body,
        )
        self.assertIn('shellui_auth_scheduled_job_overdue{job="retry_webhooks"} 0.0', body)
        self.assertIn('shellui_auth_scheduled_job_last_success_timestamp_seconds{job="retry_webhooks"}', body)
        self.assertIn('shellui_auth_scheduled_job_last_run_duration_seconds{job="retry_webhooks"}', body)
        self.assertIn('shellui_auth_scheduler_enabled', body)

        owner = User.objects.create_user(username='owner', email='o@x.test', password='x')
        client.force_authenticate(user=owner)
        self.assertEqual(client.get('/api/v1/metrics/all').status_code, 403)

    def test_company_metrics_never_include_scheduled_jobs(self):
        from apps.authapi.metrics import metrics_http_body

        company = Company.objects.create(name='Acme', slug='acme-metrics')
        self.assertNotIn(b'scheduled_job', metrics_http_body(company_id=company.pk))


@override_settings(ACTIONS_WEBHOOK_SYNC_DELIVERY=True)
class DeliveryCorrelationTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Corr', slug='corr')
        self.rule = ActionRule.objects.create(
            company=self.company,
            name='hook',
            event_type='identity.user.created',
            config={'url': 'https://example.com/h', 'secret': 's'},
        )

    def _outbox(self, **fields):
        return ActionOutbox.objects.create(
            company=self.company,
            action_rule=self.rule,
            event_type='identity.user.created',
            envelope={'id': '1', 'type': 'identity.user.created', 'data': {}},
            **fields,
        )

    @mock.patch('apps.actions.handlers.webhook.post_webhook_url', return_value=WebhookPostResult(status=200, excerpt=''))
    def test_dispatch_and_retry_attempts_carry_trigger_and_run_id(self, _post):
        first = self._outbox()
        deliver_outbox_row(first.pk)
        self.assertEqual(
            list(DeliveryAttempt.objects.filter(outbox=first).values_list('trigger', 'scheduled_job_run_id')),
            [('dispatch', None)],
        )
        second = self._outbox(status=ActionOutbox.STATUS_FAILED, next_attempt_at=timezone.now())
        # concurrency=1: SQLite test databases are not shared across threads.
        retry_pending_webhooks(concurrency=1, max_seconds=5, scheduled_job_run_id=77)
        attempt = DeliveryAttempt.objects.get(outbox=second)
        self.assertEqual((attempt.trigger, attempt.scheduled_job_run_id), ('automatic_retry', 77))

    @override_settings(EMAIL_SERVICE_API_KEY='esk_test_identity_key', EMAIL_SERVICE_URL='https://email.shellui.com')  # gitleaks:allow
    @mock.patch('apps.actions.email_client.requests.post')
    def test_email_retry_carries_run_id_and_request_id_header(self, post):
        response = mock.Mock(status_code=202, headers={})
        response.json.return_value = {'idempotent_replay': False, 'rule_enabled': True, 'messages': []}
        post.return_value = response
        row = EmailEventOutbox.objects.create(
            company=self.company,
            event_type='identity.user.created',
            idempotency_key='identity-event-1',
            body={'event_type': 'identity.user.created'},
            status=EmailEventOutbox.STATUS_FAILED,
            next_attempt_at=timezone.now(),
        )
        token = request_id_var.set('sjr-88')
        try:
            stats = retry_pending_email_events(scheduled_job_run_id=88)
        finally:
            request_id_var.reset(token)
        row.refresh_from_db()
        self.assertEqual(stats['delivered'], 1)
        self.assertEqual((row.last_trigger, row.last_scheduled_job_run_id), ('automatic_retry', 88))
        self.assertEqual(post.call_args.kwargs['headers']['X-Request-ID'], 'sjr-88')
