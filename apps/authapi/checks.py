"""Django system checks for authapi."""

from django.conf import settings
from django.core.checks import Error, register


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
                'Run `python manage.py generate_jwt_keys`, then set JWT_PRIVATE_KEY '
                'in your environment (PEM; use \\n for newlines in .env).'
            ),
            id='authapi.E001',
        )
    ]
