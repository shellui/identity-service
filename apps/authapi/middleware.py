"""Security middleware for auth abuse controls."""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse, JsonResponse

from .throttling import check_rate_limit

_LIVENESS_PATH = '/health/live'


class LivenessMiddleware:
    """Return GET /health/live before session/DB middleware (load balancer liveness)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.method == 'GET' and request.path.rstrip('/') == _LIVENESS_PATH:
            return HttpResponse('ok', content_type='text/plain')
        return self.get_response(request)


class AdminLoginRateLimitMiddleware:
    """Rate-limit POST requests to Django admin login (credential stuffing)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.method == 'POST' and request.path.rstrip('/').endswith('/admin/login'):
            limited = check_rate_limit(request, scope='admin_login')
            if limited is not None:
                retry_after = limited.headers.get('Retry-After')
                headers = {'Retry-After': retry_after} if retry_after else None
                return JsonResponse(limited.data, status=limited.status_code, headers=headers)
        return self.get_response(request)
