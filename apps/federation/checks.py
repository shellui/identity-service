"""Deployment checks for instance role."""

from django.conf import settings
from django.core.checks import Error, Warning, register

from apps.federation.parsing import region_startup_errors
from apps.federation.role import is_global, is_region


@register(deploy=True, tags='security')
def session_cookies_stay_host_only(app_configs, **kwargs):
    problems = []
    if getattr(settings, 'SESSION_COOKIE_DOMAIN', None):
        problems.append('SESSION_COOKIE_DOMAIN')
    if getattr(settings, 'CSRF_COOKIE_DOMAIN', None):
        problems.append('CSRF_COOKIE_DOMAIN')
    if not problems:
        return []
    return [
        Error(
            f'{", ".join(problems)} must stay unset so session cookies are host-only.',
            id='federation.E001',
        )
    ]


@register(deploy=True, tags='security')
def region_production_config(app_configs, **kwargs):
    if not is_region():
        return []
    messages = region_startup_errors(
        role=settings.SHELLUI_INSTANCE_ROLE,
        debug=settings.DEBUG,
        email_service_url=settings.EMAIL_SERVICE_URL,
        csrf_trusted_origins=list(settings.CSRF_TRUSTED_ORIGINS),
        allowed_hosts=list(settings.ALLOWED_HOSTS),
        issuer_url=getattr(settings, 'GLOBAL_ISSUER_URL', ''),
        jwks=getattr(settings, 'GLOBAL_JWKS', {}) or {},
        client_id=getattr(settings, 'GLOBAL_CLIENT_ID', ''),
        client_secret=getattr(settings, 'GLOBAL_CLIENT_SECRET', ''),
        jwt_issuer=getattr(settings, 'JWT_ISSUER', None),
    )
    return [Error(message, id='federation.E002') for message in messages]


@register(deploy=True)
def global_clients_configured(app_configs, **kwargs):
    if settings.DEBUG or not is_global():
        return []
    if getattr(settings, 'OIDC_CLIENTS', None):
        return []
    return [
        Warning(
            'SHELLUI_INSTANCE_ROLE=global has no OIDC_CLIENTS, so authorize will reject every client.',
            id='federation.W001',
        )
    ]
