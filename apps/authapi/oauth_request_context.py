"""Request-scoped OAuth context (thread-safe, no allauth module globals)."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token

from allauth.core import context as allauth_context
from allauth.socialaccount.models import SocialApp

_bound_oauth_social_app: ContextVar[SocialApp | None] = ContextVar(
    'shellui_bound_oauth_social_app',
    default=None,
)


def set_bound_oauth_social_app(social_app: SocialApp | None) -> Token:
    return _bound_oauth_social_app.set(social_app)


def reset_bound_oauth_social_app(token: Token) -> None:
    _bound_oauth_social_app.reset(token)


def get_bound_oauth_social_app() -> SocialApp | None:
    app = _bound_oauth_social_app.get()
    return app if isinstance(app, SocialApp) else None


@contextmanager
def oauth_allauth_request(request, *, social_app: SocialApp | None = None):
    """Run OAuth adapter code with allauth request context and optional bound SocialApp."""
    app_token = set_bound_oauth_social_app(social_app)
    with allauth_context.request_context(request):
        try:
            yield
        finally:
            reset_bound_oauth_social_app(app_token)
