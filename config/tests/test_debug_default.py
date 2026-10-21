import os
import subprocess
import sys
from pathlib import Path

from django.test import SimpleTestCase

BASE_DIR = Path(__file__).resolve().parents[2]

PROBE = (
    'import django; django.setup(); from django.conf import settings as s; '
    'print(s.DEBUG, s.SECURE_SSL_REDIRECT, s.SESSION_COOKIE_SECURE, s.CSRF_COOKIE_SECURE, '
    's.SECURE_HSTS_SECONDS > 0)'
)


class DebugDefaultTests(SimpleTestCase):
    """DEBUG is optional: unset or empty means production mode."""

    def _probe(self, debug_value):
        env = {k: v for k, v in os.environ.items() if k != 'DEBUG'}
        # An empty value stops load_dotenv from filling DEBUG from a local .env.
        env['DEBUG'] = debug_value
        env.update(
            DJANGO_SETTINGS_MODULE='config.settings',
            SECRET_KEY='test-only-debug-default-0123456789abcdef',
            JWT_ISSUER='https://id.example.com',
            JWT_AUDIENCE='shellui',
        )
        out = subprocess.run(
            [sys.executable, '-c', PROBE],
            cwd=BASE_DIR,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip().splitlines()[-1]

    def test_empty_debug_defaults_to_false_with_secure_defaults(self):
        self.assertEqual(self._probe(''), 'False True True True True')

    def test_debug_true_turns_off_secure_defaults(self):
        self.assertEqual(self._probe('true'), 'True False False False False')
