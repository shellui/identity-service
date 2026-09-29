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
        if bound is not None:
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
        if client_id:
            try:
                return SocialApp.objects.get(provider=provider, client_id=client_id)
            except SocialApp.DoesNotExist:
                raise
            except MultipleObjectsReturned as exc:
                raise MultipleObjectsReturned(
                    'Multiple SocialApp rows match this provider and client_id.'
                ) from exc
        return super().get_app(request, provider, client_id=client_id)
