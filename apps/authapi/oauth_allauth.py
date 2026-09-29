"""Bridge identity-hosted OAuth to django-allauth provider adapters."""

from __future__ import annotations

from typing import Any

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.oauth2.views import OAuth2Adapter

from apps.authapi.provider_registry import ProviderCatalogEntry, catalog_entry_for_social_app


class IdentityHostedOAuth2Adapter(OAuth2Adapter):
    """OAuth2 adapter that uses the identity-service callback URL."""

    def __init__(self, request, provider_id: str, *, callback_url: str, delegate: OAuth2Adapter):
        super().__init__(request)
        self.provider_id = provider_id
        self._callback_url = callback_url
        self._delegate = delegate

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return getattr(self._delegate, name)

    def get_callback_url(self, request, app):
        return self._callback_url

    def complete_login(self, request, app, token, **kwargs):
        return self._delegate.complete_login(request, app, token, **kwargs)

    def parse_token(self, data):
        return self._delegate.parse_token(data)


def _provider_for_social_app(request, social_app: SocialApp):
    adapter = get_adapter(request)
    lookup = social_app.provider_id or social_app.provider
    if lookup:
        try:
            return adapter.get_provider(request, provider=lookup, client_id=social_app.client_id)
        except Exception:
            pass
    return social_app.get_provider(request)


def get_identity_oauth2_adapter(
    request,
    *,
    social_app: SocialApp,
    callback_url: str,
) -> IdentityHostedOAuth2Adapter:
    provider = _provider_for_social_app(request, social_app)
    delegate = provider.get_oauth2_adapter(request)
    provider_id = str(getattr(delegate, 'provider_id', None) or social_app.provider)
    return IdentityHostedOAuth2Adapter(
        request,
        provider_id,
        callback_url=callback_url,
        delegate=delegate,
    )


def authorize_extras_for_entry(entry: ProviderCatalogEntry, *, switch_account: bool) -> dict[str, str]:
    slug = entry.docs_slug
    if slug == 'google':
        params = {'access_type': 'offline', 'prompt': 'consent'}
        if switch_account:
            params['prompt'] = 'select_account consent'
        return params
    if slug == 'microsoft' and switch_account:
        return {'prompt': 'select_account'}
    return {}


def build_allauth_authorize_url(
    request,
    *,
    entry: ProviderCatalogEntry,
    social_app: SocialApp,
    redirect_uri: str,
    state: str,
    switch_account: bool = False,
) -> tuple[str, str | None]:
    provider = _provider_for_social_app(request, social_app)
    oauth2_adapter = get_identity_oauth2_adapter(
        request,
        social_app=social_app,
        callback_url=redirect_uri,
    )
    client = oauth2_adapter.get_client(request, social_app)
    client.state = state
    scope = provider.get_scope()
    auth_params = dict(provider.get_auth_params())
    auth_params.update(authorize_extras_for_entry(entry, switch_account=switch_account))
    pkce_params = provider.get_pkce_params()
    code_verifier = pkce_params.pop('code_verifier', None)
    auth_params.update(pkce_params)
    url = client.get_redirect_url(oauth2_adapter.authorize_url, scope, auth_params)
    return url, code_verifier


def exchange_allauth_code(
    request,
    *,
    social_app: SocialApp,
    redirect_uri: str,
    pkce_code_verifier: str | None = None,
) -> tuple[Any, dict[str, Any]]:
    oauth2_adapter = get_identity_oauth2_adapter(
        request,
        social_app=social_app,
        callback_url=redirect_uri,
    )
    client = oauth2_adapter.get_client(request, social_app)
    access_token_data = oauth2_adapter.get_access_token_data(
        request,
        social_app,
        client,
        pkce_code_verifier=pkce_code_verifier,
    )
    token = oauth2_adapter.parse_token(access_token_data)
    sociallogin = oauth2_adapter.complete_login(
        request,
        social_app,
        token,
        response=access_token_data,
    )
    return sociallogin, access_token_data


def sociallogin_userinfo(sociallogin) -> dict[str, Any]:
    account = sociallogin.account
    extra = account.extra_data if isinstance(account.extra_data, dict) else {}
    data = dict(extra)
    if sociallogin.user.email and 'email' not in data:
        data['email'] = sociallogin.user.email
    if sociallogin.user.get_full_name() and 'name' not in data:
        data['name'] = sociallogin.user.get_full_name()
    if account.uid and 'id' not in data and 'sub' not in data:
        data['id'] = account.uid
        data['sub'] = account.uid
    return data


def catalog_entry_from_client(social_app: SocialApp):
    return catalog_entry_for_social_app(social_app)
