"""Provider session cookie, and strict CORS on federation endpoints."""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth import get_user_model

from apps.federation.role import is_global, is_region
from apps.federation.session import clear_cookie, set_cookie

User = get_user_model()

_STRICT_PREFIXES = (
    '/.well-known/openid-configuration',
    '/oauth/authorize',
    '/oauth/token',
    '/oauth/userinfo',
    '/oauth/backchannel-logout',
    '/oauth/silent-signin',
    '/oauth/upstream-callback',
    '/api/v1/provisioning/',
    '/api/v1/federation/',
)


class OpenIdProviderSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if not is_global():
            return response
        user_id = getattr(request, 'federation_op_user_id', None)
        if user_id:
            user = User.objects.filter(pk=user_id, is_active=True).first()
            if user is not None:
                set_cookie(response, user)
        if getattr(request, 'federation_clear_op_session', False):
            clear_cookie(response)
        return response


class FederationCorsMiddleware:
    """Replace the API-wide allow-all policy on federation endpoints."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if not (is_global() or is_region()):
            return response
        path = request.path
        if not any(path == prefix or path.startswith(prefix) for prefix in _STRICT_PREFIXES):
            return response
        for header in (
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Credentials',
            'Access-Control-Allow-Headers',
            'Access-Control-Allow-Methods',
        ):
            if header in response:
                del response[header]
        origin = request.headers.get('Origin', '')
        allowed = set(getattr(settings, 'OIDC_CORS_ALLOWED_ORIGINS', []) or [])
        if origin and origin in allowed:
            response['Access-Control-Allow-Origin'] = origin
            response['Vary'] = 'Origin'
            response['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Idempotency-Key'
            response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response['Access-Control-Allow-Credentials'] = 'false'
        return response
