"""Cache-backed rate limiting for abuse-prone auth endpoints."""

from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING, Callable, TypeVar

from django.conf import settings
from django.core.cache import cache
from rest_framework import status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from .login_audit import get_client_ip

if TYPE_CHECKING:
    from django.http import HttpRequest

ViewT = TypeVar('ViewT')


def _rate_limit_settings(scope: str) -> tuple[int, int]:
    """Return (limit, window_seconds) for a named scope."""
    defaults = getattr(settings, 'AUTH_RATE_LIMITS', {})
    spec = defaults.get(scope) or defaults.get('default') or {'limit': 60, 'window': 60}
    return int(spec['limit']), int(spec['window'])


def _cache_key(scope: str, identity: str) -> str:
    return f'auth_rate:{scope}:{identity}'


def check_rate_limit(
    request: HttpRequest,
    *,
    scope: str,
    identity: str | None = None,
    limit: int | None = None,
    window: int | None = None,
) -> Response | None:
    """
    Increment a sliding counter for ``scope`` + ``identity``.

    Returns a 429 Response when the limit is exceeded, otherwise None.
    """
    if not getattr(settings, 'AUTH_RATE_LIMIT_ENABLED', True):
        return None

    resolved_limit, resolved_window = _rate_limit_settings(scope)
    if limit is not None:
        resolved_limit = limit
    if window is not None:
        resolved_window = window

    key_identity = identity or get_client_ip(request) or 'unknown'
    cache_key = _cache_key(scope, key_identity)
    try:
        count = cache.incr(cache_key)
    except ValueError:
        cache.add(cache_key, 1, timeout=resolved_window)
        count = 1

    if count > resolved_limit:
        retry_after = resolved_window
        return Response(
            {'error': 'Too many requests. Please try again later.', 'error_code': 'rate_limited'},
            status=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={'Retry-After': str(retry_after)},
        )
    return None


def rate_limit(scope: str, *, identity: Callable[[HttpRequest], str | None] | None = None):
    """
    Decorator for DRF APIView.dispatch that enforces a rate limit before handling.

    ``identity`` may derive a bucket key (defaults to client IP from login_audit).
    """

    def decorator(cls: type[ViewT]) -> type[ViewT]:
        original_dispatch = cls.dispatch

        @wraps(original_dispatch)
        def dispatch(self, request, *args, **kwargs):
            bucket = identity(request) if identity is not None else None
            limited = check_rate_limit(request, scope=scope, identity=bucket)
            if limited is not None:
                renderer = JSONRenderer()
                limited.accepted_renderer = renderer
                limited.accepted_media_type = 'application/json'
                limited.renderer_context = self.get_renderer_context()
                return limited
            return original_dispatch(self, request, *args, **kwargs)

        cls.dispatch = dispatch
        return cls

    return decorator
