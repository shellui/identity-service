"""Single source of truth for identity-service environment variables.

Pure Python: no Django settings, database, Redis or env needed. Used by
``manage.py generate_env``, to render ``.env.example``, and by the tests that
keep both in sync with ``config/settings.py`` and ``docs/configuration.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

PLACEHOLDER = 'change-me'


@dataclass(frozen=True)
class Var:
    name: str
    default: str = ''
    group: str = ''


# Required in production (DEBUG=false). ``roles`` limits a var to one instance role.
@dataclass(frozen=True)
class Required:
    name: str
    comment: str
    roles: tuple[str, ...] = ('standalone', 'global', 'region')


REQUIRED = (
    Required('SECRET_KEY', 'Signs sessions and CSRF tokens. Generated.'),
    Required('DEBUG', 'Production mode.'),
    Required('ALLOWED_HOSTS', 'Public host names, comma-separated, no scheme.'),
    Required('CSRF_TRUSTED_ORIGINS', 'Full HTTPS origin.'),
    Required('JWT_ISSUER', 'Public identity URL (iss claim).'),
    Required('JWT_AUDIENCE', 'Token audience (aud claim).'),
    Required('JWT_PRIVATE_KEY', 'RS256 signing key, one line with \\n. Generated.'),
    Required('REDIS_URL', 'Shared cache and job broker.'),
    Required('POSTGRES_DATABASE_URL', 'PostgreSQL DSN. Leave empty to use SQLite.'),
    Required('SHELLUI_INSTANCE_ROLE', 'Instance role.', roles=('global', 'region')),
    Required('OIDC_CLIENTS', 'JSON list of relying parties.', roles=('global',)),
    Required('EMAIL_SERVICE_URL', 'This region\'s email-service origin.', roles=('region',)),
    Required('GLOBAL_ISSUER_URL', 'Global identity issuer.', roles=('region',)),
    Required('GLOBAL_JWKS', 'Pinned JWKS JSON of the global issuer.', roles=('region',)),
    Required('GLOBAL_CLIENT_ID', 'Client ID registered on the global issuer.', roles=('region',)),
    Required('GLOBAL_CLIENT_SECRET', 'Client secret from the global issuer.', roles=('region',)),
    Required('PROVISIONING_PUBLIC_KEY', 'Dashboard provisioning public key (PEM, one line).', roles=('region',)),
    Required('PROVISIONING_ISSUER', 'Dashboard issuer, for example https://dashboard.shellui.com.', roles=('region',)),
)

OPTIONAL = (
    Var('POSTGRES_DATABASE_URL', '', 'Database: SQLite unless POSTGRES_DATABASE_URL is set'),
    Var('SQLITE_PATH', 'db.sqlite3'),
    Var('POSTGRES_SSL_REQUIRE', 'true'),
    Var('POSTGRES_CONNECT_TIMEOUT', '10'),
    Var('POSTGRES_STATEMENT_TIMEOUT', '15'),
    Var('POSTGRES_LOCK_TIMEOUT', '5'),
    Var('JWT_PUBLIC_KEY', '', 'Tokens'),
    Var('JWT_KEY_ID', ''),
    Var('JWT_PREVIOUS_PUBLIC_KEY', ''),
    Var('JWT_PREVIOUS_KEY_ID', ''),
    Var('JWT_ACCEPT_HS256_LEGACY', 'false'),
    Var('JWT_ACCESS_TOKEN_LIFETIME', '5m'),
    Var('JWT_REFRESH_TOKEN_LIFETIME', '7d'),
    Var('PERSONAL_ACCESS_TOKEN_LIFETIME', '30d'),
    Var('SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE', '5m'),
    Var('OAUTH_TOKEN_DELIVERY', 'code', 'Sign-in'),
    Var('OAUTH_SESSION_CODE_TTL_SECONDS', '120'),
    Var('OAUTH_SKIP_CONFIRM_PROVIDERS', 'google'),
    Var('OAUTH_ALLOW_LOOPBACK_REDIRECTS', 'false'),
    Var('MAGIC_LINK_ENABLED', 'true'),
    Var('MAGIC_LINK_TTL_SECONDS', '1800'),
    Var('MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE', 'en'),
    Var('SCIM_ENABLED', 'true'),
    Var('SETUP_TOKEN', ''),
    Var('EMAIL_SERVICE_API_KEY', '', 'Email: email-service when EMAIL_SERVICE_API_KEY is set, else SMTP (console with DEBUG=true)'),
    Var('EMAIL_SERVICE_URL', 'https://email.shellui.com'),
    Var('EMAIL_SERVICE_TIMEOUT_SECONDS', '5'),
    Var('EMAIL_SERVICE_SEND_ATTEMPTS', '3'),
    Var('EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS', '1'),
    Var('EMAIL_BACKEND', 'django.core.mail.backends.smtp.EmailBackend'),
    Var('EMAIL_HOST', 'localhost'),
    Var('EMAIL_PORT', '25'),
    Var('EMAIL_HOST_USER', ''),
    Var('EMAIL_HOST_PASSWORD', ''),
    Var('EMAIL_USE_TLS', 'false'),
    Var('EMAIL_USE_SSL', 'false'),
    Var('EMAIL_TIMEOUT', '10'),
    Var('DEFAULT_FROM_EMAIL', 'noreply@localhost'),
    Var('ACTIONS_WEBHOOK_TIMEOUT_SECONDS', '5', 'Webhooks'),
    Var('ACTIONS_OUTBOX_MAX_ATTEMPTS', '8'),
    Var('ACTIONS_WEBHOOK_ALLOW_PRIVATE', 'false'),
    Var('ACTIONS_WEBHOOK_RETRY_LEASE_SECONDS', '120'),
    Var('ACTIONS_WEBHOOK_DISPATCH_WORKERS', '4'),
    Var('ACTIONS_WEBHOOK_SYNC_DELIVERY', 'false'),
    Var('SCHEDULER_ENABLED', 'true', 'Scheduled jobs'),
    Var('CELERY_BROKER_URL', ''),
    Var('CELERY_WORKER_CONCURRENCY', '2'),
    Var('CELERY_BEAT_SCHEDULE_FILE', '/tmp/celerybeat-schedule'),
    Var('TRUSTED_PROXY_IPS', '', 'Security'),
    Var('CORS_ALLOW_ALL_ORIGINS', 'true'),
    Var('CORS_ALLOW_CREDENTIALS', 'false'),
    Var('CORS_ALLOWED_ORIGINS', ''),
    Var('CORS_ALLOWED_ORIGIN_REGEXES', ''),
    Var('SECURE_SSL_REDIRECT', 'true'),
    Var('SECURE_HSTS_SECONDS', '31536000'),
    Var('SECURE_HSTS_INCLUDE_SUBDOMAINS', 'true'),
    Var('SECURE_HSTS_PRELOAD', 'false'),
    Var('SESSION_COOKIE_SECURE', 'true'),
    Var('CSRF_COOKIE_SECURE', 'true'),
    Var('AUTH_RATE_LIMIT_ENABLED', 'true', 'Rate limits (requests per window)'),
    Var('AUTH_RATE_LIMIT_OAUTH', '30'),
    Var('AUTH_RATE_LIMIT_TOKEN_REFRESH', '60'),
    Var('AUTH_RATE_LIMIT_SETTINGS', '30'),
    Var('AUTH_RATE_LIMIT_ADMIN_LOGIN', '10'),
    Var('AUTH_RATE_LIMIT_PAT', '30'),
    Var('AUTH_RATE_LIMIT_MAGIC_LINK', '10'),
    Var('AUTH_RATE_LIMIT_INVITATION', '30'),
    Var('LOG_LEVEL', 'INFO', 'Observability'),
    Var('SLOW_REQUEST_THRESHOLD_SECONDS', '2'),
    Var('SENTRY_DSN', ''),
    Var('SENTRY_ENVIRONMENT', 'production'),
    Var('SENTRY_RELEASE', ''),
    Var('SENTRY_TRACES_SAMPLE_RATE', '0'),
    Var('SHELLUI_GEOIP_DATABASE_PATH', ''),
    Var('GUNICORN_WORKERS', '4', 'Gunicorn (Docker entrypoint) and Docker Compose'),
    Var('GUNICORN_THREADS', '4'),
    Var('GUNICORN_TIMEOUT', '60'),
    Var('GUNICORN_GRACEFUL_TIMEOUT', '30'),
    Var('GUNICORN_KEEP_ALIVE', '75'),
    Var('GUNICORN_MAX_REQUESTS', '1000'),
    Var('GUNICORN_MAX_REQUESTS_JITTER', '200'),
    Var('IDENTITY_SERVICE_PORT', '8000'),
    Var('SHELLUI_INSTANCE_ROLE', '', 'Instance role (docs/instance-roles.md). Unset = standalone.'),
    Var('OIDC_CLIENTS', '', 'Global role (OpenID Provider)'),
    Var('OIDC_CORS_ALLOWED_ORIGINS', ''),
    Var('OIDC_SESSION_TTL_SECONDS', '43200'),
    Var('OIDC_CODE_TTL_SECONDS', '60'),
    Var('OIDC_ID_TOKEN_TTL_SECONDS', '300'),
    Var('OIDC_BACKCHANNEL_TIMEOUT_SECONDS', '3'),
    Var('GLOBAL_ISSUER_URL', '', 'Region role (required with SHELLUI_INSTANCE_ROLE=region)'),
    Var('GLOBAL_JWKS', ''),
    Var('GLOBAL_CLIENT_ID', ''),
    Var('GLOBAL_CLIENT_SECRET', ''),
    Var('GLOBAL_REDIRECT_URI', ''),
    Var('PROVISIONING_PUBLIC_KEY', '', 'Provisioning API (region role; empty PROVISIONING_PUBLIC_KEY turns it off)'),
    Var('PROVISIONING_KEY_ID', ''),
    Var('PROVISIONING_ISSUER', ''),
    Var('PROVISIONING_AUDIENCE', ''),
    Var('PROVISIONING_DEFAULT_REDIRECTS', ''),
)

ROLES = ('standalone', 'global', 'region')


def all_names() -> set[str]:
    return {v.name for v in REQUIRED} | {v.name for v in OPTIONAL}


def optional_lines(skip: frozenset[str] = frozenset()) -> list[str]:
    """Commented-out optional vars with their default, grouped by topic."""
    lines: list[str] = []
    for var in OPTIONAL:
        if var.name in skip:
            continue
        if var.group:
            lines.extend(['', f'# {var.group}'])
        lines.append(f'# {var.name}={var.default}')
    return lines


_EXAMPLE_HEADER = """\
# identity-service settings. Full reference: docs/configuration.md
# Generated from config/env_registry.py: python manage.py generate_env --example > .env.example
# Production: python manage.py generate_env --host id.example.com
# Copy to .env for local runs. Commented-out lines show the default the code uses.

# Required
# Signs sessions and CSRF tokens. At least 50 characters when DEBUG=false.
SECRET_KEY=
# Local development only. Unset means false (production).
DEBUG=true
# Public host names, comma-separated, no scheme.
ALLOWED_HOSTS=localhost,127.0.0.1

# Required when DEBUG=false (production)
JWT_ISSUER=
JWT_AUDIENCE=
JWT_PRIVATE_KEY=
REDIS_URL=
CSRF_TRUSTED_ORIGINS=

# Optional (defaults shown)"""


def render_example() -> str:
    """The content of ``.env.example`` (local development)."""
    return '\n'.join([_EXAMPLE_HEADER, *optional_lines()]) + '\n'
