"""Settings load with only the required variables (DEBUG=false) and fail fast without them."""

import os
import subprocess
import sys
from pathlib import Path

from django.test import SimpleTestCase

BASE_DIR = Path(__file__).resolve().parents[2]
PROBE = 'import django; django.setup(); from django.conf import settings as s; print("OK", s.DEBUG)'
REQUIRED = {
    'SECRET_KEY': 'test-only-minimal-env-0123456789abcdefghijklmnopqrstuvwxyz',
    'JWT_ISSUER': 'https://id.example.com',
    'JWT_AUDIENCE': 'shellui',
    'ALLOWED_HOSTS': 'id.example.com',
    'REDIS_URL': 'redis://redis:6379/0',
}


def _example_names():
    names = []
    for line in (BASE_DIR / '.env.example').read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line.startswith('#'):
            line = line.lstrip('#').strip()
        if '=' in line and line.split('=', 1)[0].isupper() and ' ' not in line.split('=', 1)[0]:
            names.append(line.split('=', 1)[0])
    return names


class MinimalEnvTests(SimpleTestCase):
    def _run(self, overrides):
        names = set(_example_names()) | set(REQUIRED) | {'DEBUG'}
        env = {k: v for k, v in os.environ.items() if k not in names}
        # Empty values stop load_dotenv from filling them from a local .env.
        env.update({name: '' for name in names})
        env.update(DJANGO_SETTINGS_MODULE='config.settings', **overrides)
        return subprocess.run(
            [sys.executable, '-c', PROBE], cwd=BASE_DIR, env=env, capture_output=True, text=True
        )

    def test_only_required_vars_load_in_production_mode(self):
        out = self._run(REQUIRED)
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertEqual(out.stdout.strip().splitlines()[-1], 'OK False')

    def test_missing_secret_key_fails_fast(self):
        out = self._run({**REQUIRED, 'SECRET_KEY': ''})
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('SECRET_KEY is not set', out.stderr)

    def test_missing_jwt_claims_fail_fast_without_printing_values(self):
        out = self._run({**REQUIRED, 'JWT_ISSUER': '', 'JWT_AUDIENCE': ''})
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('JWT_ISSUER is required', out.stderr)
        self.assertNotIn(REQUIRED['SECRET_KEY'], out.stderr)

    def test_example_lists_every_setting_once(self):
        names = _example_names()
        self.assertEqual(sorted(n for n in set(names) if names.count(n) > 1), [])
        for name in ('SECRET_KEY', 'DEBUG', 'ALLOWED_HOSTS', 'JWT_ISSUER', 'JWT_AUDIENCE', 'REDIS_URL'):
            self.assertIn(name, names)
