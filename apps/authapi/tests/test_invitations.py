from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.models import ActionOutbox, ActionRule
from apps.authapi.models import UserPreference
from apps.authapi.views import _issue_personal_access_token, _issue_shellui_tokens
from apps.companies.access import is_company_access_enabled, set_company_access
from apps.companies.models import Company, CompanyOAuthRedirect

User = get_user_model()

APP_URL = 'https://app.acme.com/'


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    AUTH_RATE_LIMIT_ENABLED=False,
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
)
class AdminInvitationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company = Company.objects.create(
            name='Invite Co',
            slug='invite-co',
            access_mode=Company.ACCESS_INVITE,
        )
        CompanyOAuthRedirect.objects.create(company=self.company, base_url='https://app.acme.com')
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@acme.com',
            password='x',
            first_name='Grace',
            last_name='Hopper',
        )
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.client.force_authenticate(user=self.owner)
        mail.outbox.clear()

    def _invite(self, body=None, **extra):
        payload = {'email': 'ada@acme.com', 'language': 'en', 'app_url': APP_URL, **(body or {})}
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(
                f'/api/v1/invitations?company_id={self.company.pk}',
                payload,
                format='json',
                **extra,
            )

    def test_creates_user_with_access_and_sends_email(self):
        response = self._invite()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(response.data['user_created'])
        user = User.objects.get(email='ada@acme.com')
        self.assertEqual(user.username, 'ada')
        self.assertFalse(user.has_usable_password())
        self.assertTrue(is_company_access_enabled(self.company, user))
        self.assertEqual(response.data['user']['id'], user.pk)
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, ['ada@acme.com'])
        self.assertEqual(message.subject, "[Shellui] You're invited to Invite Co")
        self.assertIn('Grace Hopper invited you to join Invite Co', message.body)
        self.assertIn(APP_URL, message.body)

    def test_email_uses_requested_language_and_sets_new_user_language(self):
        response = self._invite({'language': 'fr-FR'})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(mail.outbox[0].subject, '[Shellui] Invitation à rejoindre Invite Co')
        self.assertIn('vous invite à rejoindre', mail.outbox[0].body)
        user = User.objects.get(email='ada@acme.com')
        self.assertEqual(UserPreference.objects.get(user=user).language, 'fr')

    def test_existing_user_keeps_language_preference(self):
        user = User.objects.create_user(username='ada', email='Ada@acme.com', password='x')
        UserPreference.objects.create(user=user, language='en')
        response = self._invite({'language': 'fr'})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(response.data['user_created'])
        self.assertEqual(User.objects.filter(email__iexact='ada@acme.com').count(), 1)
        self.assertEqual(UserPreference.objects.get(user=user).language, 'en')
        self.assertTrue(is_company_access_enabled(self.company, user))
        self.assertIn('vous invite', mail.outbox[0].body)

    def test_existing_member_of_other_company_joins_without_new_account(self):
        other = Company.objects.create(name='Other', slug='other')
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        set_company_access(other, user, enabled=True)
        response = self._invite()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(is_company_access_enabled(self.company, user))
        self.assertTrue(is_company_access_enabled(other, user))

    def test_pending_access_request_is_approved(self):
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        set_company_access(self.company, user, enabled=False)
        response = self._invite()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(is_company_access_enabled(self.company, user))

    def test_already_member_conflict(self):
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        set_company_access(self.company, user, enabled=True)
        response = self._invite()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error_code'], 'already_member')
        self.assertEqual(len(mail.outbox), 0)

    def test_app_url_must_be_allowlisted(self):
        response = self._invite({'app_url': 'https://evil.example/'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error_code'], 'invalid_app_url')
        self.assertFalse(User.objects.filter(email='ada@acme.com').exists())

    def test_email_without_app_url_has_no_link(self):
        response = self._invite({'app_url': ''})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotIn('https://', mail.outbox[0].body)

    def test_rejects_unsupported_language(self):
        response = self._invite({'language': 'de'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('language', response.data)

    def _assert_refused(self, response, status_code=403):
        self.assertEqual(response.status_code, status_code, getattr(response, 'data', None))
        self.assertFalse(User.objects.filter(email='ada@acme.com').exists())
        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(ActionOutbox.objects.filter(event_type='identity.user.invited').exists())

    def _bearer(self, user, company=None) -> dict:
        tokens = _issue_shellui_tokens(user, company=company or self.company)
        return {'HTTP_AUTHORIZATION': f'Bearer {tokens["access_token"]}'}

    def test_anonymous_unauthorized(self):
        self.client.force_authenticate(user=None)
        self._assert_refused(self._invite(), status_code=401)

    def test_non_owner_forbidden(self):
        member = User.objects.create_user(username='member', email='member@acme.com', password='x')
        set_company_access(self.company, member, enabled=True)
        self.client.force_authenticate(user=member)
        self._assert_refused(self._invite())

    def test_non_owner_cannot_approve_pending_user(self):
        member = User.objects.create_user(username='member', email='member@acme.com', password='x')
        set_company_access(self.company, member, enabled=True)
        pending = User.objects.create_user(username='pending', email='pending@acme.com', password='x')
        set_company_access(self.company, pending, enabled=False)
        self.client.force_authenticate(user=member)
        response = self._invite({'email': 'pending@acme.com'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(is_company_access_enabled(self.company, pending))

    def test_owner_of_another_company_forbidden(self):
        other = Company.objects.create(name='Other Co', slug='other-co')
        other_owner = User.objects.create_user(username='other-owner', email='boss@other.com', password='x')
        set_company_access(other, other_owner, enabled=True)
        other.owners.add(other_owner)
        set_company_access(self.company, other_owner, enabled=True)
        self.client.force_authenticate(user=other_owner)
        self._assert_refused(self._invite())

    def test_owner_without_membership_forbidden(self):
        outsider = User.objects.create_user(username='outsider', email='out@acme.com', password='x')
        self.company.owners.add(outsider)
        self.client.force_authenticate(user=outsider)
        self._assert_refused(self._invite())

    def test_owner_with_disabled_access_forbidden(self):
        set_company_access(self.company, self.owner, enabled=False)
        self._assert_refused(self._invite())

    def test_token_for_another_company_forbidden(self):
        other = Company.objects.create(name='Other Co', slug='other-co')
        set_company_access(other, self.owner, enabled=True)
        self.client.force_authenticate(user=None)
        self._assert_refused(self._invite(**self._bearer(self.owner, company=other)))

    def test_owner_bearer_token_allowed(self):
        self.client.force_authenticate(user=None)
        response = self._invite(**self._bearer(self.owner))
        self.assertEqual(response.status_code, 201, response.data)

    def test_read_only_personal_access_token_forbidden(self):
        _row, secret = _issue_personal_access_token(
            self.owner,
            self.company,
            read_only=True,
            access_global_metrics=False,
            name='ro',
        )
        self.client.force_authenticate(user=None)
        self._assert_refused(self._invite(HTTP_AUTHORIZATION=f'Bearer {secret}'))

    def test_staff_member_allowed_without_ownership(self):
        staff = User.objects.create_user(username='staff', email='staff@acme.com', password='x', is_staff=True)
        set_company_access(self.company, staff, enabled=True)
        self.client.force_authenticate(user=staff)
        response = self._invite()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(is_company_access_enabled(self.company, User.objects.get(email='ada@acme.com')))

    def test_webhook_rule_replaces_email(self):
        ActionRule.objects.create(
            company=self.company,
            name='Invited',
            event_type='identity.user.invited',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={'url': 'https://hooks.example.com/invite', 'secret': 'whsec_test'},
        )
        response = self._invite({'language': 'fr'})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(len(mail.outbox), 0)
        data = ActionOutbox.objects.get(event_type='identity.user.invited').envelope['data']
        self.assertEqual(data['email'], 'ada@acme.com')
        self.assertEqual(data['source'], 'invitation')
        self.assertEqual(data['language'], 'fr')
        self.assertEqual(data['invited_by'], 'owner@acme.com')
        self.assertEqual(data['invitation_url'], 'https://app.acme.com/')
        self.assertTrue(data['user_created'])

    def test_user_created_event_uses_invitation_source(self):
        ActionRule.objects.create(
            company=self.company,
            name='Created',
            event_type='identity.user.created',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={'url': 'https://hooks.example.com/created', 'secret': 'whsec_test'},
        )
        self._invite()
        data = ActionOutbox.objects.get(event_type='identity.user.created').envelope['data']
        self.assertEqual(data['source'], 'invitation')

    def test_email_sent_when_webhook_emit_fails(self):
        with patch('apps.authapi.invitation_views.emit_user_invited', side_effect=RuntimeError('boom')):
            response = self._invite()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(mail.outbox), 1)

    @override_settings(AUTH_RATE_LIMIT_ENABLED=True, AUTH_RATE_LIMITS={'invitation': {'limit': 1, 'window': 60}})
    def test_rate_limited_per_company(self):
        self.assertEqual(self._invite().status_code, 201)
        response = self._invite({'email': 'bob@acme.com'})
        self.assertEqual(response.status_code, 429)
        self.assertFalse(User.objects.filter(email='bob@acme.com').exists())

    def test_invited_user_can_sign_in_on_invite_only_company(self):
        from apps.companies.access import apply_company_join

        self._invite()
        user = User.objects.get(email='ada@acme.com')
        self.assertTrue(apply_company_join(self.company, user, email=user.email).allowed)
