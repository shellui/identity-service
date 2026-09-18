from datetime import timedelta

from django.test import SimpleTestCase, override_settings

from config.settings import _env_bool, _env_duration


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
