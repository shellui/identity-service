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


class StaffTotpAdminMiddleware:
    """Require an authenticator-verified session for every page under /admin/.

    The flag is set only when the staff sign-in form accepted a code. A session that reached
    staff status any other way (an older session, another sign-in method, a session copied
    from before this was on) is signed out and sent to the staff sign-in page. It is a no-op
    when ``STAFF_ADMIN_LOGIN_HARDENED`` is off.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.conf import settings
        from django.contrib.auth import logout
        from django.shortcuts import redirect
        from django.urls import reverse
        from django.utils.http import urlencode

        from apps.authapi.staff_admin_login import STAFF_TOTP_SESSION_KEY, staff_lockout_enabled

        if staff_lockout_enabled() and request.path.startswith(reverse('admin:index')):
            user = getattr(request, 'user', None)
            if (
                user is not None
                and user.is_authenticated
                and (user.is_staff or user.is_superuser)
                and request.session.get(STAFF_TOTP_SESSION_KEY) != user.pk
                and request.path != reverse('admin:logout')
            ):
                logout(request)
                if request.path == reverse('admin:login'):
                    # Show the sign-in page again. Without this the admin login view would
                    # redirect the still-signed-in staff user back to the admin index.
                    return self.get_response(request)
                query = urlencode({'next': request.get_full_path()}) if request.method == 'GET' else ''
                login_url = reverse('admin:login')
                return redirect(f'{login_url}?{query}' if query else login_url)
        return self.get_response(request)
