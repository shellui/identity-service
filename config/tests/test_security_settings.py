import re
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client, SimpleTestCase, TestCase, override_settings

from config.settings import _env_bool, _env_duration, secure_cookie_name


class SecurityEnvHelpersTests(SimpleTestCase):
    def test_env_bool_uses_default_when_unset(self):
        self.assertFalse(_env_bool('UNLIKELY_ENV_VAR_XYZ_8651', False))
        self.assertTrue(_env_bool('UNLIKELY_ENV_VAR_XYZ_8651', True))

    def test_pat_lifetime_default_is_30_days(self):
        lifetime = _env_duration('PERSONAL_ACCESS_TOKEN_LIFETIME', timedelta(days=30))
        self.assertEqual(lifetime, timedelta(days=30))


class TransportSecuritySettingsTests(SimpleTestCase):
    @override_settings(
        SECURE_SSL_REDIRECT=True,
        SECURE_HSTS_SECONDS=31536000,
        SESSION_COOKIE_SECURE=True,
        CSRF_COOKIE_SECURE=True,
    )
    def test_production_transport_flags(self):
        from django.conf import settings

        self.assertTrue(settings.SECURE_SSL_REDIRECT)
        self.assertEqual(settings.SECURE_HSTS_SECONDS, 31536000)
        self.assertTrue(settings.SESSION_COOKIE_SECURE)
        self.assertTrue(settings.CSRF_COOKIE_SECURE)


class HostPrefixCookieNameTests(SimpleTestCase):
    def test_prefix_only_when_secure(self):
        self.assertEqual(secure_cookie_name('sessionid', secure=True), '__Host-sessionid')
        self.assertEqual(secure_cookie_name('csrftoken', secure=True), '__Host-csrftoken')
        self.assertEqual(secure_cookie_name('sessionid', secure=False), 'sessionid')
        self.assertEqual(secure_cookie_name('csrftoken', secure=False), 'csrftoken')

    def test_loaded_settings_leave_domain_unset_and_hide_csrf_from_script(self):
        from django.conf import settings

        self.assertIsNone(settings.SESSION_COOKIE_DOMAIN)
        self.assertIsNone(settings.CSRF_COOKIE_DOMAIN)
        self.assertEqual(settings.SESSION_COOKIE_PATH, '/')
        self.assertEqual(settings.CSRF_COOKIE_PATH, '/')
        self.assertTrue(settings.CSRF_COOKIE_HTTPONLY)
        if settings.SESSION_COOKIE_SECURE:
            self.assertEqual(settings.SESSION_COOKIE_NAME, '__Host-sessionid')
        else:
            self.assertEqual(settings.SESSION_COOKIE_NAME, 'sessionid')
        if settings.CSRF_COOKIE_SECURE:
            self.assertEqual(settings.CSRF_COOKIE_NAME, '__Host-csrftoken')
        else:
            self.assertEqual(settings.CSRF_COOKIE_NAME, 'csrftoken')


@override_settings(
    SESSION_COOKIE_NAME='__Host-sessionid',
    CSRF_COOKIE_NAME='__Host-csrftoken',
    SESSION_COOKIE_SECURE=True,
    CSRF_COOKIE_SECURE=True,
    CSRF_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_DOMAIN=None,
    CSRF_COOKIE_DOMAIN=None,
    ALLOWED_HOSTS=['testserver'],
)
class AdminLoginHostCookieTests(TestCase):
    """Django admin login uses the form token, not a script that reads csrftoken."""

    def test_admin_login_with_host_prefix_and_httponly_csrf(self):
        User = get_user_model()
        User.objects.create_superuser('root', 'root@example.com', 's3cret-pass')
        client = Client(enforce_csrf_checks=True)
        page = client.get('/admin/login/', secure=True)
        self.assertEqual(page.status_code, 200)
        body = page.content.decode()
        match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', body)
        self.assertIsNotNone(match)
        csrf_cookie = client.cookies['__Host-csrftoken']
        self.assertTrue(csrf_cookie['httponly'])
        self.assertTrue(csrf_cookie['secure'])
        self.assertEqual(csrf_cookie['domain'], '')
        self.assertEqual(csrf_cookie['path'], '/')
        posted = client.post(
            '/admin/login/',
            {
                'username': 'root',
                'password': 's3cret-pass',
                'csrfmiddlewaretoken': match.group(1),
                'next': '/admin/',
            },
            secure=True,
            HTTP_REFERER='https://testserver/admin/login/',
        )
        self.assertEqual(posted.status_code, 302)
        self.assertEqual(posted['Location'], '/admin/')
        session_cookie = client.cookies['__Host-sessionid']
        self.assertTrue(session_cookie['httponly'])
        self.assertTrue(session_cookie['secure'])
        self.assertEqual(session_cookie['domain'], '')
        self.assertEqual(session_cookie['path'], '/')
        index = client.get('/admin/', secure=True)
        self.assertEqual(index.status_code, 200)
