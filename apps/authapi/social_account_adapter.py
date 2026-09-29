"""Company-scoped SocialApp resolution for identity-hosted OAuth."""

from __future__ import annotations

from allauth.core.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialApp
from django.core.exceptions import MultipleObjectsReturned

from apps.authapi.oauth_social_account import get_bound_oauth_social_app


class ShellUISocialAccountAdapter(DefaultSocialAccountAdapter):
    def get_app(self, request, provider, client_id=None):
        bound = get_bound_oauth_social_app(request)
        if bound is None:
            raise SocialApp.DoesNotExist(
                'No company OAuth SocialApp is bound to this request.'
            )
        if client_id and str(bound.client_id).strip() != str(client_id).strip():
            raise SocialApp.DoesNotExist()
        provider_key = str(provider).strip().lower()
        bound_provider = str(bound.provider).strip().lower()
        bound_sub = str(getattr(bound, 'provider_id', '') or '').strip().lower()
        if bound_provider == 'openid_connect':
            if provider_key not in {bound_provider, bound_sub}:
                raise SocialApp.DoesNotExist()
        elif bound_provider != provider_key:
            raise SocialApp.DoesNotExist()
        return bound

    def get_requests_session(self):
        import functools

        import requests

        from apps.authapi.oauth_safe_http import oauth_requests_session_for_url

        class _PinningSession(requests.Session):
            def request(self, method, url, **kwargs):  # noqa: ANN001
                pinned = oauth_requests_session_for_url(str(url))
                timeout = kwargs.pop('timeout', None)
                if timeout is not None:
                    kwargs['timeout'] = timeout
                return pinned.request(method, url, **kwargs)

        session = _PinningSession()
        from allauth.socialaccount import app_settings as social_app_settings

        session.request = functools.partial(
            session.request,
            timeout=social_app_settings.REQUESTS_TIMEOUT,
        )
        return session
