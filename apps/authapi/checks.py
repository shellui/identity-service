"""Django system checks for authapi."""

from django.conf import settings
from django.core.checks import Error, register

# Django's own insecure-key warning uses 50 characters. Match that floor.
MIN_SECRET_KEY_LENGTH = 50

# Values that have been published in this repo or in Django's own docs.
_EXACT_PLACEHOLDER_SECRET_KEYS = frozenset(
    {
        'change-me-generate-a-strong-secret-key',
        'build-only-not-for-runtime',
        'your_secret_key_here',
        'replace-with-generated-key',
    }
)
_PLACEHOLDER_SECRET_KEY_PREFIXES = (
    'django-insecure-',
    'ci-only-not-for-production',
    'smoke-test-only-',
    'registry-verify-not-for-production',
    'audit-only-not-for-production',
)


def secret_key_production_problem(secret_key: str) -> str | None:
    """Return a short reason when ``secret_key`` must not be used with DEBUG=false."""
    key = (secret_key or '').strip()
    if not key:
        return 'empty'
    if key in _EXACT_PLACEHOLDER_SECRET_KEYS or key.startswith(_PLACEHOLDER_SECRET_KEY_PREFIXES):
        return 'placeholder'
    if len(key) < MIN_SECRET_KEY_LENGTH:
        return 'short'
    return None


@register()
def jwt_rs256_required_in_production(app_configs, **kwargs):
    if settings.DEBUG or not getattr(settings, 'JWT_REQUIRES_RS256', False):
        return []
    if getattr(settings, 'JWKS_ENABLED', False):
        return []
    return [
        Error(
            'JWT_PRIVATE_KEY is not set — RS256 signing is required when DEBUG=false.',
            hint=(
                'Run `uv run python manage.py generate_jwt_keys`, then set JWT_PRIVATE_KEY '
                'in your environment (PEM; use \\n for newlines in .env).'
            ),
            id='authapi.E001',
        )
    ]


@register(deploy=True, tags='security')
def jwt_issuer_audience_required_in_production(app_configs, **kwargs):
    if settings.DEBUG:
        return []
    missing = []
    if not getattr(settings, 'JWT_ISSUER', None):
        missing.append('JWT_ISSUER')
    if not getattr(settings, 'JWT_AUDIENCE', None):
        missing.append('JWT_AUDIENCE')
    if not missing:
        return []
    return [
        Error(
            f'Production requires JWT issuer and audience claims ({", ".join(missing)} not set).',
            hint=(
                'Set JWT_ISSUER to your identity-service base URL (e.g. https://auth.example.com) '
                'and JWT_AUDIENCE to the expected token audience (e.g. shellui). '
                'Issued tokens include iss/aud; verifiers should validate them.'
            ),
            id='authapi.E002',
        )
    ]


@register(deploy=True, tags='security')
def cors_allow_all_with_credentials_forbidden(app_configs, **kwargs):
    if not getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False):
        return []
    if not getattr(settings, 'CORS_ALLOW_CREDENTIALS', False):
        return []
    return [
        Error(
            'CORS_ALLOW_ALL_ORIGINS=true with CORS_ALLOW_CREDENTIALS=true is unsafe.',
            hint=(
                'Bearer JWT auth does not need credentials — leave CORS_ALLOW_CREDENTIALS=false '
                '(default) and keep allow-all, or set CORS_ALLOW_ALL_ORIGINS=false and list '
                'trusted browser origins in CORS_ALLOWED_ORIGINS.'
            ),
            id='authapi.E003',
        )
    ]


REDIS_URL_REQUIRED_MESSAGE = 'REDIS_URL is required when DEBUG is false (example: redis://redis:6379/0).'


@register(deploy=True, tags='caches')
def redis_required_in_production(app_configs, **kwargs):
    """
    Production needs Redis: the shared cache (auth rate limits, logout access-token
    denylist, OAuth state and PKCE, SAML request ids and replay protection) and the
    scheduled jobs broker. LocMem is per process, so these break across Gunicorn
    workers and containers.

    A deploy check, so `check --deploy` (run by the Docker entrypoint, and in CI) fails,
    while tests and other management commands still run. The entrypoint also exits
    early with the same message before migrations. See tools/docker-entrypoint.sh.
    """
    if settings.DEBUG:
        return []
    if (getattr(settings, 'REDIS_URL', '') or '').strip():
        return []
    return [
        Error(
            REDIS_URL_REQUIRED_MESSAGE,
            hint=(
                'Add a Redis service and set REDIS_URL on every identity-service container '
                '(web and worker), also with SCHEDULER_ENABLED=false: Redis backs the shared '
                'cache (rate limits, logout denylist, OAuth PKCE state, SAML replay '
                'protection) and the scheduled jobs. Use DEBUG=true only for local '
                'development without Redis.'
            ),
            id='authapi.E004',
        )
    ]


@register(deploy=True, tags='security')
def secret_key_refused_in_production(app_configs, **kwargs):
    if settings.DEBUG:
        return []
    problem = secret_key_production_problem(getattr(settings, 'SECRET_KEY', ''))
    if problem is None:
        return []
    return [
        Error(
            'SECRET_KEY is empty, shorter than 50 characters, or a known placeholder.',
            hint=(
                'Generate a key and set SECRET_KEY before DEBUG=false: '
                'uv run python -c "from django.core.management.utils import '
                'get_random_secret_key; print(get_random_secret_key())"'
            ),
            id='authapi.E005',
        )
    ]


@register(deploy=True, tags='security')
def jwt_hs256_legacy_disabled_in_production(app_configs, **kwargs):
    if settings.DEBUG or not getattr(settings, 'JWT_ACCEPT_HS256_LEGACY', False):
        return []
    return [
        Error(
            'JWT_ACCEPT_HS256_LEGACY=true is refused when DEBUG=false.',
            hint=(
                'HS256 tokens signed with SECRET_KEY must not be accepted in production. '
                'Set JWT_ACCEPT_HS256_LEGACY=false and sign with JWT_PRIVATE_KEY (RS256).'
            ),
            id='authapi.E006',
        )
    ]
