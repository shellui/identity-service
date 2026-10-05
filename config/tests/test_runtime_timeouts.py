import os
from unittest import mock

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from config.settings import (
    _env_non_negative_float,
    _env_positive_float,
    _postgres_timeout_options,
)


class EmailTimeoutSettingsTests(SimpleTestCase):
    def test_email_timeout_is_set(self):
        # Django's own default is None (no timeout), which can hang a login request.
        self.assertIsNotNone(settings.EMAIL_TIMEOUT)
        self.assertGreater(settings.EMAIL_TIMEOUT, 0)

    def test_email_timeout_defaults_to_10_seconds(self):
        with mock.patch.dict(os.environ, {'EMAIL_TIMEOUT': ''}):
            self.assertEqual(_env_positive_float('EMAIL_TIMEOUT', 10.0), 10.0)

    def test_email_timeout_reads_env(self):
        with mock.patch.dict(os.environ, {'EMAIL_TIMEOUT': '3.5'}):
            self.assertEqual(_env_positive_float('EMAIL_TIMEOUT', 10.0), 3.5)

    def test_email_timeout_rejects_zero(self):
        with mock.patch.dict(os.environ, {'EMAIL_TIMEOUT': '0'}):
            with self.assertRaises(ImproperlyConfigured):
                _env_positive_float('EMAIL_TIMEOUT', 10.0)

    def test_smtp_backend_uses_email_timeout(self):
        from django.core.mail.backends.smtp import EmailBackend

        self.assertEqual(EmailBackend().timeout, settings.EMAIL_TIMEOUT)


class SlowRequestThresholdSettingsTests(SimpleTestCase):
    def test_default_is_2_seconds(self):
        with mock.patch.dict(os.environ, {'SLOW_REQUEST_THRESHOLD_SECONDS': ''}):
            self.assertEqual(_env_non_negative_float('SLOW_REQUEST_THRESHOLD_SECONDS', 2.0), 2.0)

    def test_zero_is_allowed_to_turn_it_off(self):
        with mock.patch.dict(os.environ, {'SLOW_REQUEST_THRESHOLD_SECONDS': '0'}):
            self.assertEqual(_env_non_negative_float('SLOW_REQUEST_THRESHOLD_SECONDS', 2.0), 0.0)

    def test_negative_is_rejected(self):
        with mock.patch.dict(os.environ, {'SLOW_REQUEST_THRESHOLD_SECONDS': '-1'}):
            with self.assertRaises(ImproperlyConfigured):
                _env_non_negative_float('SLOW_REQUEST_THRESHOLD_SECONDS', 2.0)


class PostgresTimeoutOptionsTests(SimpleTestCase):
    def test_defaults_in_milliseconds(self):
        self.assertEqual(
            _postgres_timeout_options(15.0, 5.0),
            '-c statement_timeout=15000 -c lock_timeout=5000',
        )

    def test_zero_turns_a_deadline_off(self):
        self.assertEqual(_postgres_timeout_options(0, 5.0), '-c lock_timeout=5000')
        self.assertEqual(_postgres_timeout_options(15.0, 0), '-c statement_timeout=15000')
        self.assertEqual(_postgres_timeout_options(0, 0), '')

    def test_sqlite_has_no_postgres_options(self):
        if settings.DATABASES['default']['ENGINE'] != 'django.db.backends.sqlite3':
            self.skipTest('Only relevant when tests run on SQLite')
        options = settings.DATABASES['default'].get('OPTIONS', {})
        self.assertNotIn('options', options)


class LoggingSettingsTests(SimpleTestCase):
    def test_errors_reach_stdout_without_debug_filter(self):
        handler = settings.LOGGING['handlers']['console']
        self.assertEqual(handler['stream'], 'ext://sys.stdout')
        self.assertNotIn('require_debug_true', handler.get('filters', []))
        self.assertEqual(settings.LOGGING['loggers']['django.request']['level'], 'WARNING')
        self.assertIn('console', settings.LOGGING['loggers']['django.request']['handlers'])

    def test_request_id_middleware_runs_first(self):
        self.assertEqual(settings.MIDDLEWARE[0], 'config.request_context.RequestIdMiddleware')
