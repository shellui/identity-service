"""manage.py generate_env and the env registry (config/env_registry.py)."""

import os
import re
import subprocess
import sys
from pathlib import Path

from django.test import SimpleTestCase

from apps.authapi.checks import secret_key_production_problem
from apps.authapi.jwks import load_signing_key
from config import env_registry as reg

BASE_DIR = Path(__file__).resolve().parents[2]
CODE_PATTERNS = (
    re.compile(r"getenv\(\s*'([A-Z][A-Z0-9_]+)'"),
    re.compile(r"_env_[a-z_]+\(\s*'([A-Z][A-Z0-9_]+)'"),
    re.compile(r'\$\{([A-Z][A-Z0-9_]+):'),
)
INTERNAL = {'APP_USER', 'DJANGO_SETTINGS_MODULE'}


def _run(*args, env=None):
    return subprocess.run(
        [sys.executable, 'manage.py', 'generate_env', *args],
        cwd=BASE_DIR,
        env=env if env is not None else {'PATH': os.environ.get('PATH', '')},
        capture_output=True,
        text=True,
        check=True,
    )


def _parse(text):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        name, _, value = line.partition('=')
        assert re.fullmatch(r'[A-Z][A-Z0-9_]*', name), line
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        values[name] = value
    return values


def _code_names():
    names = set()
    files = [*BASE_DIR.joinpath('config').glob('*.py'), *BASE_DIR.joinpath('apps').rglob('*.py'),
             BASE_DIR / 'tools' / 'docker-entrypoint.sh']
    for path in files:
        if 'tests' in path.parts:
            continue
        text = path.read_text(encoding='utf-8')
        for pattern in CODE_PATTERNS:
            names.update(pattern.findall(text))
    return names - INTERNAL


class RegistryTests(SimpleTestCase):
    def test_registry_matches_code(self):
        self.assertEqual(sorted(_code_names() - reg.all_names()), [], 'read by code, missing in env_registry')
        self.assertEqual(sorted(reg.all_names() - _code_names() - {'IDENTITY_SERVICE_PORT'}), [], 'stale in env_registry')

    def test_env_example_is_rendered_from_registry(self):
        self.assertEqual((BASE_DIR / '.env.example').read_text(encoding='utf-8'), reg.render_example(),
                         'run: python manage.py generate_env --example > .env.example')

    def test_docs_reference_every_setting(self):
        docs = (BASE_DIR / 'docs' / 'configuration.md').read_text(encoding='utf-8')
        missing = sorted(n for n in reg.all_names() if f'`{n}`' not in docs)
        self.assertEqual(missing, [])


class GenerateEnvTests(SimpleTestCase):
    def test_works_with_zero_env_and_warns_on_stderr(self):
        out = _run('--bits', '2048')
        self.assertIn('secret manager', out.stderr)
        self.assertNotIn('SECRET_KEY', out.stderr)
        values = _parse(out.stdout)
        self.assertEqual(values['DEBUG'], 'false')
        self.assertIsNone(secret_key_production_problem(values['SECRET_KEY']))
        key = load_signing_key(private_pem=values['JWT_PRIVATE_KEY'], kid=values['JWT_KEY_ID'])
        self.assertEqual(key.kid, values['JWT_KEY_ID'])

    def test_host_derives_urls(self):
        values = _parse(_run('--host', 'https://ID.example.com/', '--bits', '2048').stdout)
        self.assertEqual(values['ALLOWED_HOSTS'], 'id.example.com')
        self.assertEqual(values['CSRF_TRUSTED_ORIGINS'], 'https://id.example.com')
        self.assertEqual(values['JWT_ISSUER'], 'https://id.example.com')

    def test_two_runs_give_different_secrets(self):
        a = _parse(_run('--bits', '2048').stdout)
        b = _parse(_run('--bits', '2048').stdout)
        self.assertNotEqual(a['SECRET_KEY'], b['SECRET_KEY'])
        self.assertNotEqual(a['JWT_PRIVATE_KEY'], b['JWT_PRIVATE_KEY'])

    def test_region_role_adds_placeholders_never_a_key(self):
        values = _parse(_run('--role', 'region', '--bits', '2048').stdout)
        self.assertEqual(values['SHELLUI_INSTANCE_ROLE'], 'region')
        self.assertEqual(values['PROVISIONING_PUBLIC_KEY'], reg.PLACEHOLDER)
        self.assertIn('GLOBAL_ISSUER_URL', values)

    def test_optional_lists_every_setting_once(self):
        out = _run('--optional', '--bits', '2048').stdout
        names = re.findall(r'^#? ?([A-Z][A-Z0-9_]+)=', out, re.M)
        self.assertEqual(sorted(n for n in set(names) if names.count(n) > 1), [])
        self.assertTrue(reg.all_names() <= set(names))

    def test_settings_load_with_generated_block(self):
        values = _parse(_run('--host', 'id.example.com', '--bits', '2048').stdout)
        values['POSTGRES_DATABASE_URL'] = ''  # SQLite, nothing to connect to
        env = {'PATH': os.environ.get('PATH', ''), 'DJANGO_SETTINGS_MODULE': 'config.settings'}
        env.update({name: '' for name in reg.all_names()})
        env.update(values)
        probe = ('import django; django.setup(); from django.conf import settings as s; '
                 'print(s.DEBUG, s.JWKS_ENABLED, s.JWT_ISSUER)')
        out = subprocess.run([sys.executable, '-c', probe], cwd=BASE_DIR, env=env,
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr[-1500:])
        self.assertEqual(out.stdout.strip().splitlines()[-1], 'False True https://id.example.com')
        check = subprocess.run([sys.executable, 'manage.py', 'check', '--deploy', '--fail-level', 'ERROR'],
                               cwd=BASE_DIR, env=env, capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr[-1500:])
