"""Direct send of magic links and invitations through email-service."""

import json
from unittest.mock import Mock, patch

import requests
from django.core import mail
from django.core.cache import cache
from django.core.mail.backends.base import BaseEmailBackend
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.email_client import invitation_idempotency_key, magic_link_idempotency_key
from apps.authapi.models import MagicLinkToken
from apps.authapi.views import _issue_shellui_tokens
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyInvitation, CompanyOAuthRedirect
from django.contrib.auth import get_user_model

User = get_user_model()

# Not a live credential. gitleaks:allow
_API_KEY = 'esk_test_identity_key'  # gitleaks:allow

_SETTINGS = dict(
    ALLOWED_HOSTS=['testserver'],
    AUTH_RATE_LIMIT_ENABLED=False,
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    JWT_ISSUER='https://auth.example.com',
    MAGIC_LINK_ENABLED=True,
    EMAIL_SERVICE_URL='https://email.shellui.com',
    EMAIL_SERVICE_API_KEY=_API_KEY,
    EMAIL_SERVICE_SEND_ATTEMPTS=3,
    EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS=0,
)


def _accepted(status=202, code=''):
    response = Mock()
    response.status_code = status
    response.headers = {}
    response.json.return_value = (
        {'idempotent_replay': False, 'messages': [{'id': 'msg_abc', 'status': 'queued'}]}
        if status == 202
        else {'error_code': code}
    )
    return response


class FailingBackend(BaseEmailBackend):
    def send_messages(self, email_messages):
        raise OSError('smtp down')


@override_settings(**_SETTINGS)
class DirectSendTests(TestCase):
    def setUp(self):
        cache.clear()
        mail.outbox.clear()
        self.client = APIClient()
        self.company = Company.objects.create(name='Acme', slug='acme')
        CompanyOAuthRedirect.objects.create(company=self.company, base_url='https://app.example.com')
        self.user = User.objects.create_user(
            username='ada',
            email='ada@acme.com',
            password='unused',
            first_name='Ada',
            last_name='Lovelace',
        )
        set_company_access(self.company, self.user, enabled=True)
        self.owner = User.objects.create_user(
            username='grace',
            email='grace@acme.com',
            password='unused',
            first_name='Grace',
        )
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.client.force_authenticate(user=self.owner)

    def _magic(self, email='ada@acme.com', language='en'):
        return self.client.post(
            '/api/v1/magic-link/request',
            {
                'company_id': self.company.id,
                'email': email,
                'redirect_to': 'https://app.example.com/login/callback',
                'language': language,
            },
            format='json',
        )

    def _invite(self, **extra):
        body = {'email': 'new@acme.com', 'language': 'fr', 'app_url': 'https://app.example.com/'}
        body.update(extra)
        return self.client.post(
            f'/api/v1/invitations?company_id={self.company.pk}',
            body,
            format='json',
        )

    def test_idempotency_key_is_stable_and_omits_the_token(self):
        first = magic_link_idempotency_key(company_id=42, user_id=7, request_id='req_1')
        second = magic_link_idempotency_key(company_id=42, user_id=7, request_id='req_1')
        self.assertEqual(first, second)
        self.assertEqual(first, 'magic-link-42-user-7-req_1')
        self.assertNotIn('secret-token', first)
        self.assertEqual(
            invitation_idempotency_key(company_id=42, invitation_id=9),
            invitation_idempotency_key(company_id=42, invitation_id=9),
        )

    @patch('apps.actions.email_client.requests.post')
    def test_magic_link_send_uses_email_service(self, post):
        post.return_value = _accepted()
        with self.assertLogs('apps.actions.email_client', level='WARNING') as logs:
            response = self._magic()
            # A successful send logs nothing at WARNING. Force one line so assertLogs is satisfied.
            import logging

            logging.getLogger('apps.actions.email_client').warning('email_service_test_marker')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(mail.outbox, [])
        post.assert_called_once()
        url = post.call_args.args[0]
        self.assertEqual(url, 'https://email.shellui.com/api/v1/send')
        self.assertEqual(post.call_args.kwargs['headers']['Authorization'], f'Bearer {_API_KEY}')
        body = post.call_args.kwargs['json']
        self.assertEqual(body['template_key'], 'identity.auth.magic_link.requested')
        self.assertEqual(body['ttl_seconds'], 120)
        self.assertNotIn('lane', body)
        self.assertEqual(body['language'], 'en')
        self.assertEqual(body['to'], [{'email': 'ada@acme.com', 'user_id': self.user.pk}])
        self.assertEqual(body['variables']['company_name'], 'Acme')
        self.assertEqual(body['variables']['recipient_name'], 'Ada Lovelace')
        self.assertIn('token=', body['variables']['magic_link_url'])
        token = body['variables']['magic_link_url'].split('token=', 1)[1].split('&', 1)[0]
        self.assertNotIn(token, body['idempotency_key'])
        self.assertEqual(
            body['idempotency_key'],
            magic_link_idempotency_key(
                company_id=self.company.pk,
                user_id=self.user.pk,
                request_id=MagicLinkToken.objects.get().pk,
            ),
        )
        logged = '\n'.join(logs.output)
        self.assertNotIn(_API_KEY, logged)
        self.assertNotIn(token, logged)

    @patch('apps.actions.email_client.requests.post')
    def test_outsider_omits_user_id(self, post):
        post.return_value = _accepted()
        User.objects.create_user(username='out', email='out@acme.com', password='unused')
        response = self._magic(email='out@acme.com')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(post.call_args.kwargs['json']['to'], [{'email': 'out@acme.com'}])

    @patch('apps.actions.email_client.requests.post')
    def test_invitation_send_uses_email_service(self, post):
        post.return_value = _accepted()
        response = self._invite()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(mail.outbox, [])
        body = post.call_args.kwargs['json']
        invitation = CompanyInvitation.objects.get()
        self.assertEqual(body['template_key'], 'identity.user.invited')
        self.assertEqual(body['ttl_seconds'], 300)
        self.assertEqual(body['language'], 'fr')
        self.assertEqual(body['to'], [{'email': 'new@acme.com'}])
        self.assertEqual(body['variables']['invitation_url'], 'https://app.example.com/')
        self.assertEqual(body['variables']['inviter_name'], 'Grace')
        self.assertEqual(
            body['idempotency_key'],
            invitation_idempotency_key(company_id=self.company.pk, invitation_id=invitation.pk),
        )

    @patch('apps.actions.email_client.requests.post')
    def test_retries_keep_the_same_idempotency_key_then_use_smtp(self, post):
        post.side_effect = requests.ConnectionError('down')
        response = self._magic()
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(post.call_count, 3)
        keys = [call.kwargs['json']['idempotency_key'] for call in post.call_args_list]
        bodies = [json.dumps(call.kwargs['json'], sort_keys=True) for call in post.call_args_list]
        self.assertEqual(len(set(keys)), 1)
        self.assertEqual(len(set(bodies)), 1)
        token = mail.outbox[0].body.split('token=', 1)[1].split('&', 1)[0].strip()
        self.assertNotIn(token, keys[0])

    @patch('apps.actions.email_client.requests.post')
    def test_both_paths_fail_with_email_unavailable(self, post):
        post.side_effect = requests.ConnectionError('down')
        with override_settings(EMAIL_BACKEND='apps.authapi.tests.test_email_service_send.FailingBackend'):
            response = self._magic()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data, {'error_code': 'email_unavailable'})
        self.assertEqual(mail.outbox, [])
        self.assertFalse(MagicLinkToken.objects.exists())

    @patch('apps.actions.email_client.requests.post')
    def test_invitation_both_paths_fail(self, post):
        post.side_effect = requests.ConnectionError('down')
        with override_settings(EMAIL_BACKEND='apps.authapi.tests.test_email_service_send.FailingBackend'):
            response = self._invite()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data, {'error_code': 'email_unavailable'})
        self.assertFalse(CompanyInvitation.objects.exists())

    @patch('apps.actions.email_client.requests.post')
    def test_suppressed_recipient_is_not_retried_or_sent_over_smtp(self, post):
        post.return_value = _accepted(422, 'recipient_suppressed')
        response = self._magic()
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.data, {'error_code': 'recipient_suppressed'})
        self.assertEqual(post.call_count, 1)
        self.assertEqual(mail.outbox, [])
        self.assertFalse(MagicLinkToken.objects.exists())

    @patch('apps.actions.email_client.requests.post')
    def test_rate_limit_does_not_fall_back_to_smtp(self, post):
        post.return_value = _accepted(429, 'rate_limited')
        response = self._magic()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data, {'error_code': 'email_unavailable'})
        self.assertEqual(post.call_count, 3)
        self.assertEqual(mail.outbox, [])
        self.assertFalse(MagicLinkToken.objects.exists())

    @patch('apps.actions.email_client.requests.post')
    def test_company_rate_limit_is_returned_without_smtp(self, post):
        post.return_value = _accepted(429, 'company_rate_limited')
        response = self._magic()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.data, {'error_code': 'company_rate_limited'})
        self.assertEqual(post.call_count, 3)
        self.assertEqual(mail.outbox, [])
        self.assertFalse(MagicLinkToken.objects.exists())

    @patch('apps.actions.email_client.requests.post')
    def test_provider_not_configured_is_returned_without_smtp(self, post):
        post.return_value = _accepted(409, 'provider_not_configured')
        response = self._invite()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data, {'error_code': 'provider_not_configured'})
        self.assertEqual(post.call_count, 3)
        self.assertEqual(mail.outbox, [])
        self.assertFalse(CompanyInvitation.objects.exists())

    @patch('apps.actions.email_client.requests.post')
    def test_platform_sender_not_allowed_is_returned_without_smtp(self, post):
        post.return_value = _accepted(409, 'platform_sender_not_allowed')
        response = self._magic()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data, {'error_code': 'platform_sender_not_allowed'})
        self.assertEqual(mail.outbox, [])

    @patch('apps.actions.email_client.requests.post')
    def test_auth_link_errors_are_returned_without_smtp(self, post):
        post.return_value = _accepted(400, 'auth_link_host_not_allowed')
        response = self._magic()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, {'error_code': 'auth_link_host_not_allowed'})
        self.assertEqual(post.call_count, 1)
        self.assertEqual(mail.outbox, [])
        post.return_value = _accepted(400, 'auth_link_missing')
        response = self._magic()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, {'error_code': 'auth_link_missing'})
        self.assertEqual(mail.outbox, [])

    @patch('apps.actions.email_client.requests.post')
    def test_validation_error_does_not_fall_back_to_smtp(self, post):
        post.return_value = _accepted(400, 'validation_failed')
        response = self._invite()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data, {'error_code': 'email_unavailable'})
        self.assertEqual(post.call_count, 1)
        self.assertEqual(mail.outbox, [])

    @patch('apps.actions.email_client.requests.post')
    def test_missing_app_url_still_uses_email_service(self, post):
        post.return_value = _accepted()
        response = self._invite(app_url='')
        self.assertEqual(response.status_code, 201, response.data)
        post.assert_called_once()
        self.assertEqual(mail.outbox, [])
        body = post.call_args.kwargs['json']
        self.assertEqual(body['template_key'], 'identity.user.invited')
        self.assertEqual(body['variables']['invitation_url'], 'https://auth.example.com/')

    @override_settings(EMAIL_SERVICE_API_KEY='')
    @patch('apps.actions.email_client.requests.post')
    def test_unset_key_uses_smtp_only(self, post):
        response = self._magic()
        self.assertEqual(response.status_code, 200, response.data)
        post.assert_not_called()
        self.assertEqual(len(mail.outbox), 1)
