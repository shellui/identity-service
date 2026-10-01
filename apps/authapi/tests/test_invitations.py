import re
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.models import ActionOutbox, ActionRule
from apps.authapi.magic_link import create_magic_link_token
from apps.authapi.models import UserPreference
from apps.authapi.views import _issue_personal_access_token, _issue_shellui_tokens
from apps.companies.access import (
    apply_company_join,
    is_company_access_enabled,
    is_login_blocked_by_revoked_invitation,
    set_company_access,
)
from apps.companies.models import Company, CompanyInvitation, CompanyOAuthRedirect

User = get_user_model()

APP_URL = 'https://app.acme.com/'


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    AUTH_RATE_LIMIT_ENABLED=False,
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    JWT_ISSUER='https://auth.example.com',
    MAGIC_LINK_ENABLED=True,
)
class InvitationTestCase(TestCase):
    def setUp(self):
        cache.clear()
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

    def _list(self, **extra):
        return self.client.get(f'/api/v1/invitations?company_id={self.company.pk}', **extra)

    def _revoke(self, invitation_id, **extra):
        return self.client.post(
            f'/api/v1/invitations/{invitation_id}/revoke?company_id={self.company.pk}',
            **extra,
        )

    def _delete(self, invitation_id, **extra):
        return self.client.delete(
            f'/api/v1/invitations/{invitation_id}?company_id={self.company.pk}',
            **extra,
        )

    def _hook(self, event_type):
        ActionRule.objects.create(
            company=self.company,
            name=event_type,
            event_type=event_type,
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={'url': 'https://hooks.example.com/h', 'secret': 'whsec_test'},
        )


class InvitationCreateTests(InvitationTestCase):
    def test_stores_pending_invitation_without_creating_user(self):
        response = self._invite()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(User.objects.filter(email__iexact='ada@acme.com').exists())
        invitation = CompanyInvitation.objects.get(company=self.company, email='ada@acme.com')
        self.assertEqual(invitation.status, CompanyInvitation.STATUS_PENDING)
        self.assertEqual(invitation.invited_by, self.owner)
        self.assertEqual(response.data['invitation']['id'], invitation.pk)
        self.assertEqual(response.data['invitation']['status'], 'pending')
        self.assertNotIn('user', response.data)
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, ['ada@acme.com'])
        self.assertEqual(message.subject, "[Shellui] You're invited to Invite Co")
        self.assertIn('Grace Hopper invited you to join Invite Co', message.body)
        self.assertIn(APP_URL, message.body)

    def test_email_is_normalized(self):
        response = self._invite({'email': ' Ada@ACME.com '})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['invitation']['email'], 'ada@acme.com')

    def test_email_uses_requested_language(self):
        response = self._invite({'language': 'fr-FR'})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['invitation']['language'], 'fr')
        self.assertEqual(mail.outbox[0].subject, '[Shellui] Invitation à rejoindre Invite Co')
        self.assertIn('vous invite à rejoindre', mail.outbox[0].body)

    def test_existing_account_elsewhere_gets_no_access_until_sign_in(self):
        other = Company.objects.create(name='Other', slug='other')
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        set_company_access(other, user, enabled=True)
        response = self._invite()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(is_company_access_enabled(self.company, user))
        self.assertEqual(set(response.data), {'invitation'})

    def test_already_member_conflict(self):
        user = User.objects.create_user(username='ada', email='Ada@acme.com', password='x')
        set_company_access(self.company, user, enabled=True)
        response = self._invite()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error_code'], 'already_member')
        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(CompanyInvitation.objects.exists())

    def test_pending_access_request_can_be_invited(self):
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        set_company_access(self.company, user, enabled=False)
        response = self._invite()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(is_company_access_enabled(self.company, user))

    def test_already_invited_conflict(self):
        self.assertEqual(self._invite().status_code, 201)
        response = self._invite()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error_code'], 'already_invited')
        self.assertEqual(CompanyInvitation.objects.count(), 1)
        self.assertEqual(len(mail.outbox), 1)

    def test_same_email_can_be_invited_by_another_company(self):
        self._invite()
        other = Company.objects.create(name='Other', slug='other')
        CompanyInvitation.objects.create(company=other, email='ada@acme.com')
        self.assertEqual(CompanyInvitation.objects.filter(email='ada@acme.com').count(), 2)

    def test_app_url_must_be_allowlisted(self):
        response = self._invite({'app_url': 'https://evil.example/'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error_code'], 'invalid_app_url')
        self.assertFalse(CompanyInvitation.objects.exists())

    def test_email_without_app_url_has_no_link(self):
        response = self._invite({'app_url': ''})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotIn('https://', mail.outbox[0].body)

    def test_rejects_unsupported_language(self):
        response = self._invite({'language': 'de'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('language', response.data)

    def test_webhook_rule_replaces_email_and_only_invited_event_fires(self):
        self._hook('identity.user.invited')
        self._hook('identity.user.created')
        response = self._invite({'language': 'fr'})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(ActionOutbox.objects.filter(event_type='identity.user.created').exists())
        data = ActionOutbox.objects.get(event_type='identity.user.invited').envelope['data']
        self.assertEqual(data['invitation_id'], response.data['invitation']['id'])
        self.assertEqual(data['email'], 'ada@acme.com')
        self.assertEqual(data['source'], 'invitation')
        self.assertEqual(data['language'], 'fr')
        self.assertEqual(data['invited_by'], 'owner@acme.com')
        self.assertEqual(data['invitation_url'], APP_URL)
        self.assertNotIn('user_id', data)

    def test_webhook_payload_does_not_reveal_account_in_other_company(self):
        other = Company.objects.create(name='Other', slug='other')
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        set_company_access(other, user, enabled=True)
        self._hook('identity.user.invited')
        self._invite()
        data = ActionOutbox.objects.get(event_type='identity.user.invited').envelope['data']
        self.assertNotIn('user_id', data)
        self.assertNotIn('username', data)

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
        self.assertFalse(CompanyInvitation.objects.filter(email='bob@acme.com').exists())


class InvitationAccessControlTests(InvitationTestCase):
    def _assert_refused(self, response, status_code=403):
        self.assertEqual(response.status_code, status_code, getattr(response, 'data', None))
        self.assertFalse(CompanyInvitation.objects.exists())
        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(ActionOutbox.objects.filter(event_type='identity.user.invited').exists())

    def _bearer(self, user, company=None) -> dict:
        tokens = _issue_shellui_tokens(user, company=company or self.company)
        return {'HTTP_AUTHORIZATION': f'Bearer {tokens["access_token"]}'}

    def _member(self):
        member = User.objects.create_user(username='member', email='member@acme.com', password='x')
        set_company_access(self.company, member, enabled=True)
        return member

    def test_anonymous_unauthorized(self):
        self.client.force_authenticate(user=None)
        self._assert_refused(self._invite(), status_code=401)

    def test_non_owner_forbidden(self):
        self.client.force_authenticate(user=self._member())
        self._assert_refused(self._invite())

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

    def test_non_owner_cannot_list_revoke_or_delete(self):
        invitation = CompanyInvitation.objects.create(company=self.company, email='ada@acme.com')
        revoked = CompanyInvitation.objects.create(
            company=self.company,
            email='bob@acme.com',
            status=CompanyInvitation.STATUS_REVOKED,
        )
        self.client.force_authenticate(user=self._member())
        self.assertEqual(self._list().status_code, 403)
        self.assertEqual(self._revoke(invitation.pk).status_code, 403)
        self.assertEqual(self._delete(revoked.pk).status_code, 403)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, CompanyInvitation.STATUS_PENDING)
        self.assertTrue(CompanyInvitation.objects.filter(pk=revoked.pk).exists())


class InvitationListAndRevokeTests(InvitationTestCase):
    def test_lists_pending_and_blocking_revoked_only(self):
        pending = CompanyInvitation.objects.create(company=self.company, email='pending@acme.com', invited_by=self.owner)
        revoked = CompanyInvitation.objects.create(
            company=self.company,
            email='revoked@acme.com',
            status=CompanyInvitation.STATUS_REVOKED,
        )
        CompanyInvitation.objects.create(
            company=self.company,
            email='accepted@acme.com',
            status=CompanyInvitation.STATUS_ACCEPTED,
        )
        CompanyInvitation.objects.create(
            company=self.company,
            email='again@acme.com',
            status=CompanyInvitation.STATUS_REVOKED,
        )
        again = CompanyInvitation.objects.create(company=self.company, email='again@acme.com')
        other = Company.objects.create(name='Other', slug='other')
        CompanyInvitation.objects.create(company=other, email='elsewhere@acme.com')

        response = self._list()
        self.assertEqual(response.status_code, 200)
        rows = {row['email']: row for row in response.data['results']}
        self.assertEqual(set(rows), {'pending@acme.com', 'revoked@acme.com', 'again@acme.com'})
        self.assertEqual(rows['pending@acme.com']['id'], pending.pk)
        self.assertEqual(rows['pending@acme.com']['invited_by']['email'], 'owner@acme.com')
        self.assertEqual(rows['revoked@acme.com']['id'], revoked.pk)
        self.assertEqual(rows['revoked@acme.com']['status'], 'revoked')
        self.assertEqual(rows['again@acme.com']['id'], again.pk)
        self.assertEqual(rows['again@acme.com']['status'], 'pending')

    def test_list_hides_emails_that_already_have_access(self):
        CompanyInvitation.objects.create(company=self.company, email='ada@acme.com')
        user = User.objects.create_user(username='ada', email='Ada@acme.com', password='x')
        set_company_access(self.company, user, enabled=True)
        self.assertEqual(self._list().data['results'], [])

    def test_revoke_marks_revoked_and_emits_event(self):
        self._hook('identity.user.invitation_revoked')
        invitation_id = self._invite().data['invitation']['id']
        response = self._revoke(invitation_id)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['invitation']['status'], 'revoked')
        invitation = CompanyInvitation.objects.get(pk=invitation_id)
        self.assertEqual(invitation.status, CompanyInvitation.STATUS_REVOKED)
        self.assertEqual(invitation.revoked_by, self.owner)
        self.assertIsNotNone(invitation.revoked_at)
        data = ActionOutbox.objects.get(event_type='identity.user.invitation_revoked').envelope['data']
        self.assertEqual(data['invitation_id'], invitation_id)
        self.assertEqual(data['email'], 'ada@acme.com')
        self.assertEqual(data['revoked_by'], 'owner@acme.com')

    def test_revoke_twice_conflict(self):
        invitation_id = self._invite().data['invitation']['id']
        self._revoke(invitation_id)
        response = self._revoke(invitation_id)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error_code'], 'invitation_not_pending')

    def test_cannot_revoke_invitation_of_another_company(self):
        other = Company.objects.create(name='Other', slug='other')
        invitation = CompanyInvitation.objects.create(company=other, email='ada@acme.com')
        self.assertEqual(self._revoke(invitation.pk).status_code, 404)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, CompanyInvitation.STATUS_PENDING)

    def test_delete_revoked_removes_it_and_lifts_block(self):
        invitation_id = self._invite().data['invitation']['id']
        self._revoke(invitation_id)
        self.assertTrue(is_login_blocked_by_revoked_invitation(self.company, 'ada@acme.com'))
        response = self._delete(invitation_id)
        self.assertEqual(response.status_code, 204)
        self.assertFalse(CompanyInvitation.objects.filter(pk=invitation_id).exists())
        self.assertEqual(self._list().data['results'], [])
        self.assertFalse(is_login_blocked_by_revoked_invitation(self.company, 'ada@acme.com'))

    def test_delete_removes_older_revoked_rows_for_same_email(self):
        accepted = CompanyInvitation.objects.create(
            company=self.company,
            email='ada@acme.com',
            status=CompanyInvitation.STATUS_ACCEPTED,
        )
        CompanyInvitation.objects.create(
            company=self.company,
            email='ada@acme.com',
            status=CompanyInvitation.STATUS_REVOKED,
        )
        latest = CompanyInvitation.objects.create(
            company=self.company,
            email='ada@acme.com',
            status=CompanyInvitation.STATUS_REVOKED,
        )
        other = Company.objects.create(name='Other', slug='other')
        elsewhere = CompanyInvitation.objects.create(
            company=other,
            email='ada@acme.com',
            status=CompanyInvitation.STATUS_REVOKED,
        )
        self.assertEqual(self._delete(latest.pk).status_code, 204)
        self.assertEqual(
            list(CompanyInvitation.objects.filter(company=self.company).values_list('pk', flat=True)),
            [accepted.pk],
        )
        self.assertTrue(CompanyInvitation.objects.filter(pk=elsewhere.pk).exists())
        self.assertFalse(is_login_blocked_by_revoked_invitation(self.company, 'ada@acme.com'))

    def test_cannot_delete_pending_invitation(self):
        invitation_id = self._invite().data['invitation']['id']
        response = self._delete(invitation_id)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error_code'], 'invitation_not_revoked')
        self.assertTrue(CompanyInvitation.objects.filter(pk=invitation_id).exists())

    def test_cannot_delete_invitation_of_another_company(self):
        other = Company.objects.create(name='Other', slug='other')
        invitation = CompanyInvitation.objects.create(
            company=other,
            email='ada@acme.com',
            status=CompanyInvitation.STATUS_REVOKED,
        )
        self.assertEqual(self._delete(invitation.pk).status_code, 404)
        self.assertTrue(CompanyInvitation.objects.filter(pk=invitation.pk).exists())

    def test_reinvite_after_revoke(self):
        first_id = self._invite().data['invitation']['id']
        self._revoke(first_id)
        response = self._invite()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotEqual(response.data['invitation']['id'], first_id)
        self.assertEqual(len(mail.outbox), 2)


class InvitationSignInTests(InvitationTestCase):
    def setUp(self):
        super().setUp()
        self.anon = APIClient()

    def _request_link(self, email='ada@acme.com'):
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            return self.anon.post(
                '/api/v1/magic-link/request',
                {'company_id': self.company.id, 'email': email, 'redirect_to': f'{APP_URL}login/callback'},
                format='json',
            )

    def _verify(self, raw_token):
        return self.anon.post(
            '/api/v1/magic-link/verify',
            {'token': raw_token, 'company_id': self.company.id},
            format='json',
        )

    def _sign_in(self, email='ada@acme.com'):
        self.assertEqual(self._request_link(email).status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        raw = re.search(r'token=([^&\s]+)', mail.outbox[0].body).group(1)
        return self._verify(raw)

    def test_magic_link_sign_in_accepts_pending_invitation(self):
        self._hook('identity.user.created')
        invitation_id = self._invite({'language': 'fr'}).data['invitation']['id']
        response = self._sign_in()
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn('access_token', response.data)
        user = User.objects.get(email='ada@acme.com')
        self.assertTrue(is_company_access_enabled(self.company, user))
        self.assertEqual(UserPreference.objects.get(user=user).language, 'fr')
        invitation = CompanyInvitation.objects.get(pk=invitation_id)
        self.assertEqual(invitation.status, CompanyInvitation.STATUS_ACCEPTED)
        self.assertEqual(invitation.accepted_user, user)
        created = ActionOutbox.objects.get(event_type='identity.user.created').envelope['data']
        self.assertEqual(created['source'], 'magic_link')

    def test_uninvited_sign_in_stays_pending_on_invite_only_company(self):
        response = self._sign_in()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['error_code'], 'access_pending')

    def test_existing_account_elsewhere_keeps_language(self):
        other = Company.objects.create(name='Other', slug='other')
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        set_company_access(other, user, enabled=True)
        UserPreference.objects.create(user=user, language='en')
        self._invite({'language': 'fr'})
        self.assertEqual(self._sign_in().status_code, 200)
        self.assertTrue(is_company_access_enabled(self.company, user))
        self.assertTrue(is_company_access_enabled(other, user))
        self.assertEqual(UserPreference.objects.get(user=user).language, 'en')

    def test_revoked_invitation_gets_no_magic_link(self):
        self._revoke(self._invite().data['invitation']['id'])
        response = self._request_link()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['ok'])
        self.assertEqual(len(mail.outbox), 0)

    def test_link_issued_before_revoke_is_refused_without_creating_account(self):
        invitation_id = self._invite().data['invitation']['id']
        _row, raw = create_magic_link_token(
            company=self.company,
            email='ada@acme.com',
            redirect_to=f'{APP_URL}login/callback',
        )
        self._revoke(invitation_id)
        response = self._verify(raw)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['error_code'], 'invitation_revoked')
        self.assertFalse(User.objects.filter(email__iexact='ada@acme.com').exists())

    def test_revoked_blocks_existing_account_even_on_public_company(self):
        self.company.access_mode = Company.ACCESS_PUBLIC
        self.company.save()
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        self._revoke(self._invite().data['invitation']['id'])
        decision = apply_company_join(self.company, user, email='ada@acme.com')
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, 'invitation_revoked')
        self.assertFalse(is_company_access_enabled(self.company, user))

    def test_revoked_blocks_on_stored_email_without_verified_email(self):
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        self._revoke(self._invite().data['invitation']['id'])
        decision = apply_company_join(self.company, user, email=None)
        self.assertEqual(decision.error_code, 'invitation_revoked')

    def test_reinvite_after_revoke_allows_sign_in(self):
        self._revoke(self._invite().data['invitation']['id'])
        self._invite()
        self.assertEqual(self._sign_in().status_code, 200)

    def test_pending_invitation_needs_verified_email(self):
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        self._invite()
        decision = apply_company_join(self.company, user, email=None)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, 'access_pending')
        self.assertEqual(
            CompanyInvitation.objects.get(email='ada@acme.com').status,
            CompanyInvitation.STATUS_PENDING,
        )

    def test_enabled_member_not_blocked_by_old_revoked_invitation(self):
        CompanyInvitation.objects.create(
            company=self.company,
            email='ada@acme.com',
            status=CompanyInvitation.STATUS_REVOKED,
        )
        user = User.objects.create_user(username='ada', email='ada@acme.com', password='x')
        set_company_access(self.company, user, enabled=True)
        self.assertTrue(apply_company_join(self.company, user, email='ada@acme.com').allowed)
        self.assertFalse(is_login_blocked_by_revoked_invitation(self.company, 'ada@acme.com'))

    def test_revoked_check_is_scoped_to_company(self):
        other = Company.objects.create(name='Other', slug='other')
        CompanyInvitation.objects.create(
            company=other,
            email='ada@acme.com',
            status=CompanyInvitation.STATUS_REVOKED,
        )
        self.assertTrue(is_login_blocked_by_revoked_invitation(other, 'ada@acme.com'))
        self.assertFalse(is_login_blocked_by_revoked_invitation(self.company, 'ada@acme.com'))
