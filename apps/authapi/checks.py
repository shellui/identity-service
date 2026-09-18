"""Django system checks for authapi."""

from django.conf import settings
from django.core.checks import Error, Warning, register


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


@register(deploy=True, tags='security')
def jwt_hs256_legacy_disabled_in_production(app_configs, **kwargs):
    if settings.DEBUG or not getattr(settings, 'JWT_ACCEPT_HS256_LEGACY', False):
        return []
    if not getattr(settings, 'JWKS_ENABLED', False):
        return []
    return [
        Warning(
            'JWT_ACCEPT_HS256_LEGACY=true in production — SECRET_KEY can still forge JWTs.',
            hint=(
                'After RS256 migration and token expiry, set JWT_ACCEPT_HS256_LEGACY=false '
                'so only RS256 tokens signed with JWT_PRIVATE_KEY are accepted.'
            ),
            id='authapi.W001',
        )
    ]
