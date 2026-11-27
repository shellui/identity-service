"""Django staff sign-in: lockout and TOTP when DEBUG is false."""

from __future__ import annotations

import time
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.authapi.models import StaffAdminGuard
from apps.authapi.staff_totp import generate_totp_secret, totp_at

User = get_user_model()


def _code(secret: str, offset: int = 0) -> str:
    return totp_at(secret, int(time.time()) // 30 + offset)


def _enroll(user, secret: str, *, confirmed: bool = True) -> StaffAdminGuard:
    guard = StaffAdminGuard(user=user, totp_confirmed_at=timezone.now() if confirmed else None)
    guard.set_secret(secret)
    guard.save()
    return guard


@override_settings(
    DEBUG=False,
    STAFF_ADMIN_LOGIN_HARDENED=True,
    AUTH_RATE_LIMIT_ENABLED=False,
    STAFF_ADMIN_LOCKOUT_FAILURES=2,
    STAFF_ADMIN_LOCKOUT_SECONDS=900,
)
class StaffAdminLoginProductionTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='ops',
            email='ops@shellui.test',
            password='pw-staff',
            is_staff=True,
        )

    def _post(self, **extra):
        data = {'username': 'ops', 'password': 'pw-staff', 'next': '/admin/'}
        data.update(extra)
        return self.client.post('/admin/login/?next=/admin/', data)

    def test_password_alone_is_refused_until_an_authenticator_is_confirmed(self):
        page = self.client.get('/admin/login/')
        self.assertContains(page, 'Authenticator code')
        response = self._post()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'no authenticator')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_confirmed_code_signs_in_and_a_wrong_code_does_not(self):
        secret = generate_totp_secret()
        _enroll(self.user, secret)
        wrong = self._post(otp='000000')
        self.assertEqual(wrong.status_code, 200)
        self.assertContains(wrong, 'not valid')
        ok = self._post(otp=_code(secret))
        self.assertEqual(ok.status_code, 302)
        self.assertEqual(ok['Location'], '/admin/')

    def test_repeated_failures_lock_the_account(self):
        secret = generate_totp_secret()
        _enroll(self.user, secret)
        self._post(password='wrong-1', otp=_code(secret))
        self._post(password='wrong-2', otp=_code(secret))
        locked = self._post(otp=_code(secret))
        self.assertEqual(locked.status_code, 200)
        self.assertContains(locked, 'temporarily locked')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_enroll_command_hides_the_secret_unless_asked_and_confirms_it(self):
        quiet = StringIO()
        call_command('enroll_staff_totp', 'ops', stdout=quiet)
        text = quiet.getvalue()
        self.assertNotIn('otpauth://', text)
        self.assertIn('--show-secret', text)
        secret = StaffAdminGuard.objects.get(user=self.user).secret
        self.assertTrue(secret)
        self.assertNotIn(secret, text)

        shown = StringIO()
        call_command('enroll_staff_totp', 'ops', show_secret=True, stdout=shown)
        self.assertEqual(shown.getvalue().splitlines()[0].strip(), secret)
        self.assertNotIn('otpauth://', shown.getvalue())

        uri = StringIO()
        call_command('enroll_staff_totp', 'ops', show_uri=True, stdout=uri)
        self.assertIn('otpauth://totp/', uri.getvalue())

        confirmed = StringIO()
        call_command('enroll_staff_totp', 'ops', code=_code(secret), stdout=confirmed)
        self.assertIn('confirmed', confirmed.getvalue())
        guard = StaffAdminGuard.objects.get(user=self.user)
        self.assertIsNotNone(guard.totp_confirmed_at)
        self.assertGreater(guard.totp_last_step, 0)
        with self.assertRaises(CommandError):
            call_command('enroll_staff_totp', 'ops')
        with self.assertRaises(CommandError):
            call_command('enroll_staff_totp', 'ops', show_secret=True)

    def test_the_confirmation_code_cannot_be_used_to_sign_in(self):
        call_command('enroll_staff_totp', 'ops', stdout=StringIO())
        secret = StaffAdminGuard.objects.get(user=self.user).secret
        code = _code(secret)
        call_command('enroll_staff_totp', 'ops', code=code, stdout=StringIO())
        response = self._post(otp=code)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'not valid')

    def test_rotate_replaces_the_secret_and_unconfirms_it(self):
        secret = generate_totp_secret()
        _enroll(self.user, secret)
        call_command('enroll_staff_totp', 'ops', rotate=True, stdout=StringIO())
        guard = StaffAdminGuard.objects.get(user=self.user)
        self.assertNotEqual(guard.secret, secret)
        self.assertIsNone(guard.totp_confirmed_at)
        self.assertEqual(guard.totp_last_step, 0)

    def test_a_used_code_cannot_sign_in_again(self):
        secret = generate_totp_secret()
        _enroll(self.user, secret)
        code = _code(secret)
        self.assertEqual(self._post(otp=code).status_code, 302)
        self.client.logout()
        replay = self._post(otp=code)
        self.assertEqual(replay.status_code, 200)
        self.assertContains(replay, 'not valid')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_an_older_step_than_the_last_accepted_is_refused(self):
        secret = generate_totp_secret()
        _enroll(self.user, secret)
        self.assertEqual(self._post(otp=_code(secret, 0)).status_code, 302)
        self.client.logout()
        older = self._post(otp=_code(secret, -1))
        self.assertEqual(older.status_code, 200)
        self.assertContains(older, 'not valid')

    def test_a_newer_step_after_the_last_is_accepted(self):
        secret = generate_totp_secret()
        _enroll(self.user, secret)
        self.assertEqual(self._post(otp=_code(secret, -1)).status_code, 302)
        self.client.logout()
        self.assertEqual(self._post(otp=_code(secret, 0)).status_code, 302)

    def test_the_secret_is_encrypted_at_rest(self):
        from django.db import connection

        secret = generate_totp_secret()
        _enroll(self.user, secret)
        with connection.cursor() as cursor:
            cursor.execute('select totp_secret from authapi_staffadminguard')
            raw = cursor.fetchone()[0]
        self.assertTrue(raw.startswith('enc1:'))
        self.assertNotIn(secret, raw)
        self.assertEqual(StaffAdminGuard.objects.get(user=self.user).secret, secret)

    def test_a_secret_that_cannot_be_decrypted_counts_as_not_enrolled(self):
        secret = generate_totp_secret()
        _enroll(self.user, secret)
        with override_settings(SECRET_KEY='a-different-key-' + 'x' * 40, SECRET_KEY_FALLBACKS=[]):
            self.assertEqual(StaffAdminGuard.objects.get(user=self.user).secret, '')
            response = self._post(otp=_code(secret))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'no authenticator')

    def test_an_old_secret_key_in_fallbacks_still_decrypts(self):
        secret = generate_totp_secret()
        _enroll(self.user, secret)
        from django.conf import settings as dj_settings

        with override_settings(SECRET_KEY='a-new-key-' + 'y' * 40, SECRET_KEY_FALLBACKS=[dj_settings.SECRET_KEY]):
            self.assertEqual(StaffAdminGuard.objects.get(user=self.user).secret, secret)


@override_settings(
    DEBUG=False,
    STAFF_ADMIN_LOGIN_HARDENED=True,
    AUTH_RATE_LIMIT_ENABLED=False,
)
class StaffAdminSessionFlagTests(TestCase):
    """Every /admin/ page needs a session that signed in with a verified code."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='ops', email='ops@shellui.test', password='pw-staff', is_staff=True, is_superuser=True
        )
        self.secret = generate_totp_secret()
        _enroll(self.user, self.secret)

    def _sign_in(self):
        return self.client.post(
            '/admin/login/?next=/admin/',
            {'username': 'ops', 'password': 'pw-staff', 'next': '/admin/', 'otp': _code(self.secret)},
        )

    def test_a_verified_session_reaches_the_admin(self):
        self.assertEqual(self._sign_in().status_code, 302)
        for path in ('/admin/', '/admin/auth/user/'):
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_a_session_without_the_flag_is_signed_out_on_every_admin_path(self):
        for path in ('/admin/', '/admin/auth/user/', '/admin/auth/user/add/'):
            self.client.force_login(self.user)
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertTrue(response['Location'].startswith('/admin/login/'), path)
            self.assertNotIn('_auth_user_id', self.client.session, path)

    def test_a_post_without_the_flag_is_refused_and_signs_out(self):
        self.client.force_login(self.user)
        response = self.client.post('/admin/auth/user/add/', {'username': 'x'})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].startswith('/admin/login/'))
        self.assertFalse(User.objects.filter(username='x').exists())
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_the_login_page_shows_for_an_unverified_session_without_a_redirect_loop(self):
        self.client.force_login(self.user)
        page = self.client.get('/admin/login/')
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, 'Authenticator code')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_a_flag_from_another_account_does_not_carry_over(self):
        other = User.objects.create_user(username='other', password='pw', is_staff=True)
        self.client.force_login(other)
        session = self.client.session
        session['staff_totp_verified_user_id'] = self.user.pk
        session.save()
        self.assertEqual(self.client.get('/admin/').status_code, 302)

    def test_a_password_only_sign_in_never_sets_the_flag(self):
        from apps.authapi.staff_admin_login import STAFF_TOTP_SESSION_KEY

        self.client.force_login(self.user)
        self.assertNotIn(STAFF_TOTP_SESSION_KEY, self.client.session)

    def test_logout_stays_reachable(self):
        self.client.force_login(self.user)
        self.assertNotEqual(self.client.post('/admin/logout/').status_code, 500)

    @override_settings(STAFF_ADMIN_LOGIN_HARDENED=False)
    def test_the_flag_is_not_required_when_hardening_is_off(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get('/admin/').status_code, 200)


@override_settings(DEBUG=True, STAFF_ADMIN_LOGIN_HARDENED=False, AUTH_RATE_LIMIT_ENABLED=False)
class StaffAdminLoginDebugTests(TestCase):
    def test_debug_sign_in_does_not_ask_for_a_code(self):
        User.objects.create_user(username='ops', password='pw-staff', is_staff=True)
        client = Client()
        page = client.get('/admin/login/')
        self.assertNotContains(page, 'Authenticator code')
        response = client.post(
            '/admin/login/?next=/admin/',
            {'username': 'ops', 'password': 'pw-staff', 'next': '/admin/'},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/admin/')
