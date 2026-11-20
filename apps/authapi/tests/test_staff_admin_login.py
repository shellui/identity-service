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


def _code(secret: str) -> str:
    return totp_at(secret, int(time.time()) // 30)


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
        StaffAdminGuard.objects.create(
            user=self.user,
            totp_secret=secret,
            totp_confirmed_at=timezone.now(),
        )
        wrong = self._post(otp='000000')
        self.assertEqual(wrong.status_code, 200)
        self.assertContains(wrong, 'not valid')
        ok = self._post(otp=_code(secret))
        self.assertEqual(ok.status_code, 302)
        self.assertEqual(ok['Location'], '/admin/')

    def test_repeated_failures_lock_the_account(self):
        secret = generate_totp_secret()
        StaffAdminGuard.objects.create(
            user=self.user,
            totp_secret=secret,
            totp_confirmed_at=timezone.now(),
        )
        self._post(password='wrong-1', otp=_code(secret))
        self._post(password='wrong-2', otp=_code(secret))
        locked = self._post(otp=_code(secret))
        self.assertEqual(locked.status_code, 200)
        self.assertContains(locked, 'temporarily locked')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_enroll_command_prints_a_secret_and_confirms_it(self):
        out = StringIO()
        call_command('enroll_staff_totp', 'ops', stdout=out)
        text = out.getvalue()
        self.assertIn('otpauth://totp/', text)
        secret = text.splitlines()[0].strip()
        code = _code(secret)
        confirmed = StringIO()
        call_command('enroll_staff_totp', 'ops', code=code, stdout=confirmed)
        self.assertIn('confirmed', confirmed.getvalue())
        guard = StaffAdminGuard.objects.get(user=self.user)
        self.assertIsNotNone(guard.totp_confirmed_at)
        with self.assertRaises(CommandError):
            call_command('enroll_staff_totp', 'ops')


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
