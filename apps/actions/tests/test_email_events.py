"""Forwarding catalog events to email-service, including retries."""

from datetime import timedelta
from unittest.mock import Mock, patch

import requests
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.actions.email_events import retry_pending_email_events
from apps.actions.emit import emit_event
from apps.actions.models import EmailEventOutbox, EventLog
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

# Not a live credential. gitleaks:allow
_API_KEY = 'esk_test_identity_key'  # gitleaks:allow


def _response(status=202, body=None):
    response = Mock()
    response.status_code = status
    response.headers = {}
    response.json.return_value = body if body is not None else {
        'idempotent_replay': False,
        'rule_enabled': True,
        'messages': [],
    }
    return response


@override_settings(
    EMAIL_SERVICE_API_KEY=_API_KEY,
    EMAIL_SERVICE_URL='https://email.shellui.com',
    EMAIL_SERVICE_SEND_ATTEMPTS=2,
    EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS=0,
    ACTIONS_WEBHOOK_SYNC_DELIVERY=True,
)
class EmailEventForwardTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-mail')
        self.owner = User.objects.create_user(
            username='grace',
            email='grace@acme.com',
            password='unused',
        )
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.member = User.objects.create_user(
            username='ada',
            email='ada@acme.com',
            password='unused',
        )
        set_company_access(self.company, self.member, enabled=True)

    def _emit(self, event_type, payload):
        with self.captureOnCommitCallbacks(execute=True):
            return emit_event(event_type, self.company, payload)

    @patch('apps.actions.email_client.requests.post')
    def test_user_created_is_forwarded(self, post):
        post.return_value = _response()
        self._emit(
            'identity.user.created',
            {'user_id': self.member.pk, 'email': 'ada@acme.com', 'source': 'oauth', 'language': 'fr'},
        )
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], 'https://email.shellui.com/api/v1/events')
        self.assertEqual(post.call_args.kwargs['headers']['Authorization'], f'Bearer {_API_KEY}')
        body = post.call_args.kwargs['json']
        self.assertEqual(body['service'], 'identity')
        self.assertEqual(body['event_type'], 'identity.user.created')
        self.assertEqual(body['company_id'], self.company.pk)
        self.assertEqual(body['language'], 'fr')
        self.assertEqual(body['recipients'], [{'email': 'ada@acme.com', 'user_id': self.member.pk}])
        self.assertEqual(body['payload']['company_name'], 'Acme')
        self.assertEqual(body['payload']['source'], 'oauth')
        self.assertNotIn('email', body['payload'])
        logged = EventLog.objects.get(event_type='identity.user.created')
        self.assertEqual(body['idempotency_key'], f'identity-event-{logged.pk}')
        row = EmailEventOutbox.objects.get()
        self.assertEqual(row.status, EmailEventOutbox.STATUS_DELIVERED)

    @patch('apps.actions.email_client.requests.post')
    def test_group_event_uses_company_owners_when_the_payload_has_no_email(self, post):
        post.return_value = _response()
        self._emit(
            'identity.group.created',
            {'group_id': 3, 'display_name': 'Engineering', 'source': 'manual'},
        )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['recipients'], [{'email': 'grace@acme.com', 'user_id': self.owner.pk}])
        self.assertEqual(body['payload']['display_name'], 'Engineering')

    @patch('apps.actions.email_client.requests.post')
    def test_token_name_is_mapped_for_the_template(self, post):
        post.return_value = _response()
        self._emit(
            'identity.scim.token.created',
            {'token_id': '00000000-0000-0000-0000-000000000001', 'name': 'Okta prod', 'token_prefix': 'abc123'},
        )
        payload = post.call_args.kwargs['json']['payload']
        self.assertEqual(payload['token_name'], 'Okta prod')
        self.assertNotIn('name', payload)
        self.assertEqual(payload['token_prefix'], 'abc123')

    @patch('apps.actions.email_client.requests.post')
    def test_direct_send_events_and_sign_ins_are_not_forwarded(self, post):
        self._emit(
            'identity.auth.magic_link.requested',
            {'email': 'ada@acme.com', 'magic_link_url': 'https://auth.example.com/secret', 'request_id': '1'},
        )
        self._emit('identity.user.invited', {'email': 'ada@acme.com', 'invitation_id': 1})
        self._emit('identity.auth.login.succeeded', {'provider': 'magic_link'})
        post.assert_not_called()
        self.assertFalse(EmailEventOutbox.objects.exists())
        self.assertTrue(EventLog.objects.filter(event_type='identity.auth.login.succeeded').exists())

    @patch('apps.actions.email_client.requests.post')
    def test_forwarding_retries_then_delivers(self, post):
        calls = {'n': 0}

        def fake_post(*args, **kwargs):
            calls['n'] += 1
            if calls['n'] < 2:
                raise requests.ConnectionError('down')
            return _response()

        post.side_effect = fake_post
        self._emit(
            'identity.user.deleted',
            {'user_id': self.member.pk, 'email': 'ada@acme.com', 'source': 'admin'},
        )
        row = EmailEventOutbox.objects.get()
        self.assertEqual(row.status, EmailEventOutbox.STATUS_FAILED)
        first_key = row.body['idempotency_key']
        row.next_attempt_at = timezone.now() - timedelta(seconds=1)
        row.locked_until = None
        row.save(update_fields=['next_attempt_at', 'locked_until'])
        stats = retry_pending_email_events()
        self.assertEqual(stats['delivered'], 1)
        row.refresh_from_db()
        self.assertEqual(row.status, EmailEventOutbox.STATUS_DELIVERED)
        self.assertEqual(post.call_count, 2)
        keys = [call.kwargs['json']['idempotency_key'] for call in post.call_args_list]
        self.assertEqual(set(keys), {first_key})

    @patch('apps.actions.email_client.requests.post')
    def test_lane_pause_stays_retryable(self, post):
        post.return_value = _response(409, {'error_code': 'lane_paused'})
        self._emit(
            'identity.user.deleted',
            {'user_id': self.member.pk, 'email': 'ada@acme.com', 'source': 'admin'},
        )
        row = EmailEventOutbox.objects.get()
        self.assertEqual(row.status, EmailEventOutbox.STATUS_FAILED)
        self.assertEqual(row.last_error, 'lane_paused')
        self.assertEqual(post.call_count, 1)

    @patch('apps.actions.email_client.requests.post')
    def test_permanent_error_is_not_retried(self, post):
        post.return_value = _response(400, {'error_code': 'validation_failed'})
        self._emit(
            'identity.user.deleted',
            {'user_id': self.member.pk, 'email': 'ada@acme.com', 'source': 'admin'},
        )
        row = EmailEventOutbox.objects.get()
        self.assertEqual(row.status, EmailEventOutbox.STATUS_DEAD)
        self.assertEqual(row.last_error, 'validation_failed')
        stats = retry_pending_email_events()
        self.assertEqual(stats['processed'], 0)
        self.assertEqual(post.call_count, 1)

    @patch('apps.actions.email_client.requests.post')
    def test_skipped_reason_is_finished(self, post):
        post.return_value = _response(202, {
            'idempotent_replay': False,
            'rule_enabled': False,
            'skipped_reason': 'rule_disabled',
            'messages': [],
        })
        self._emit(
            'identity.user.deleted',
            {'user_id': self.member.pk, 'email': 'ada@acme.com', 'source': 'admin'},
        )
        row = EmailEventOutbox.objects.get()
        self.assertEqual(row.status, EmailEventOutbox.STATUS_DELIVERED)
        self.assertEqual(post.call_count, 1)
        stats = retry_pending_email_events()
        self.assertEqual(stats['processed'], 0)

    @patch('apps.actions.email_client.requests.post')
    def test_not_found_is_retried_with_the_same_key(self, post):
        post.return_value = _response(404, {'error_code': 'not_found'})
        self._emit(
            'identity.user.deleted',
            {'user_id': self.member.pk, 'email': 'ada@acme.com', 'source': 'admin'},
        )
        row = EmailEventOutbox.objects.get()
        self.assertEqual(row.status, EmailEventOutbox.STATUS_FAILED)
        key = row.body['idempotency_key']
        post.return_value = _response()
        row.next_attempt_at = timezone.now() - timedelta(seconds=1)
        row.locked_until = None
        row.save(update_fields=['next_attempt_at', 'locked_until'])
        retry_pending_email_events()
        row.refresh_from_db()
        self.assertEqual(row.status, EmailEventOutbox.STATUS_DELIVERED)
        keys = [call.kwargs['json']['idempotency_key'] for call in post.call_args_list]
        self.assertEqual(keys, [key, key])

    @patch('apps.actions.email_client.requests.post')
    def test_suppressed_event_is_permanent(self, post):
        post.return_value = _response(422, {'error_code': 'recipient_suppressed'})
        self._emit(
            'identity.user.deleted',
            {'user_id': self.member.pk, 'email': 'ada@acme.com', 'source': 'admin'},
        )
        row = EmailEventOutbox.objects.get()
        self.assertEqual(row.status, EmailEventOutbox.STATUS_DEAD)
        self.assertEqual(post.call_count, 1)

    @patch('apps.actions.email_client.requests.post')
    def test_retry_after_sets_the_next_attempt(self, post):
        response = _response(429, {'error_code': 'company_rate_limited'})
        response.headers = {'Retry-After': '120'}
        post.return_value = response
        self._emit(
            'identity.user.deleted',
            {'user_id': self.member.pk, 'email': 'ada@acme.com', 'source': 'admin'},
        )
        row = EmailEventOutbox.objects.get()
        self.assertEqual(row.status, EmailEventOutbox.STATUS_FAILED)
        wait = (row.next_attempt_at - timezone.now()).total_seconds()
        self.assertGreaterEqual(wait, 100)
        self.assertLessEqual(wait, 130)


@override_settings(EMAIL_SERVICE_API_KEY='', ACTIONS_WEBHOOK_SYNC_DELIVERY=True)
class EmailEventUnconfiguredTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme', slug='acme-off')

    @patch('apps.actions.email_client.requests.post')
    def test_no_forwarding_when_unconfigured(self, post):
        with self.captureOnCommitCallbacks(execute=True):
            emit_event(
                'identity.user.created',
                self.company,
                {'user_id': 1, 'email': 'ada@acme.com', 'source': 'admin'},
            )
        self.assertFalse(EmailEventOutbox.objects.exists())
        post.assert_not_called()
        self.assertTrue(EventLog.objects.filter(event_type='identity.user.created').exists())
