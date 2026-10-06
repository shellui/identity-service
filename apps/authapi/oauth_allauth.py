"""Bridge identity-hosted OAuth to django-allauth provider adapters."""

from __future__ import annotations

import types
from typing import Any

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialApp
from django.core.exceptions import ImproperlyConfigured, MultipleObjectsReturned

from apps.authapi.oauth_adapter_settings import apply_oauth_adapter_settings
from apps.authapi.oauth_request_context import oauth_allauth_request
from apps.authapi.oauth_social_account import bind_oauth_social_app
from apps.authapi.provider_registry import ProviderCatalogEntry, catalog_entry_for_social_app


def _provider_for_social_app(request, social_app: SocialApp):
    adapter = get_adapter(request)
    lookup = social_app.provider_id or social_app.provider
    try:
        return adapter.get_provider(
            request,
            provider=lookup,
            client_id=social_app.client_id,
        )
    except SocialApp.DoesNotExist as exc:
        raise ImproperlyConfigured(
            f'SocialApp {social_app.pk} is not configured for provider {lookup!r}.'
        ) from exc
    except MultipleObjectsReturned as exc:
        raise ImproperlyConfigured(
            f'Multiple SocialApp rows match provider {lookup!r} and client_id.'
        ) from exc


def _patch_delegate_callback(delegate, callback_url: str) -> None:
    delegate.get_callback_url = types.MethodType(
        lambda self, request, app: callback_url,
        delegate,
    )


def _ensure_delegate_get_client_uses_identity_callback(delegate, callback_url: str) -> None:
    from allauth.socialaccount.providers.oauth2.views import OAuth2Adapter

    _patch_delegate_callback(delegate, callback_url)
    if getattr(delegate.get_client, '__func__', None) is OAuth2Adapter.get_client:
        return
    delegate.get_client = types.MethodType(OAuth2Adapter.get_client, delegate)


def split_pkce_authorize_params(request, social_app: SocialApp) -> tuple[dict[str, str], str | None]:
    bind_oauth_social_app(request, social_app)
    with oauth_allauth_request(request, social_app=social_app):
        provider = _provider_for_social_app(request, social_app)
        params = dict(provider.get_pkce_params())
    verifier = params.pop('code_verifier', None)
    if isinstance(verifier, str):
        verifier = verifier.strip() or None
    return params, verifier


def get_identity_oauth2_adapter(
    request,
    *,
    social_app: SocialApp,
    callback_url: str,
):
    provider = _provider_for_social_app(request, social_app)
    entry = catalog_entry_for_social_app(social_app)
    delegate = provider.get_oauth2_adapter(request)
    apply_oauth_adapter_settings(delegate, social_app=social_app, entry=entry)
    _ensure_delegate_get_client_uses_identity_callback(delegate, callback_url)
    return delegate


def authorize_extras_for_entry(
    entry: ProviderCatalogEntry,
    *,
    switch_account: bool,
    oauth_nonce: str | None = None,
) -> dict[str, str]:
    slug = entry.docs_slug
    if slug == 'google':
        params = {'access_type': 'offline', 'prompt': 'consent'}
        if switch_account:
            params['prompt'] = 'select_account consent'
        return params
    if slug == 'microsoft' and switch_account:
        return {'prompt': 'select_account'}
    if slug == 'apple':
        params = {'response_mode': 'form_post', 'response_type': 'code id_token'}
        nonce = str(oauth_nonce or '').strip()
        if nonce:
            params['nonce'] = nonce
        return params
    return {}


def build_allauth_authorize_url(
    request,
    *,
    entry: ProviderCatalogEntry,
    social_app: SocialApp,
    redirect_uri: str,
    state: str,
    switch_account: bool = False,
    pkce_params: dict | None = None,
    oauth_nonce: str | None = None,
) -> str:
    bind_oauth_social_app(request, social_app)
    with oauth_allauth_request(request, social_app=social_app):
        provider = _provider_for_social_app(request, social_app)
        oauth2_adapter = get_identity_oauth2_adapter(
            request,
            social_app=social_app,
            callback_url=redirect_uri,
        )
        client = oauth2_adapter.get_client(request, social_app)
        client.state = state
        scope = provider.get_scope()
        if entry.docs_slug == 'twitch':
            from apps.authapi.oauth_twitch import TWITCH_SCOPE

            scope = list(TWITCH_SCOPE)
        auth_params = dict(provider.get_auth_params())
        auth_params.update(
            authorize_extras_for_entry(
                entry,
                switch_account=switch_account,
                oauth_nonce=oauth_nonce,
            )
        )
        if pkce_params is not None:
            auth_params.update(pkce_params)
        return client.get_redirect_url(oauth2_adapter.authorize_url, scope, auth_params)


def exchange_allauth_code(
    request,
    *,
    social_app: SocialApp,
    redirect_uri: str,
    pkce_code_verifier: str | None = None,
) -> tuple[Any, dict[str, Any]]:
    bind_oauth_social_app(request, social_app)
    with oauth_allauth_request(request, social_app=social_app):
        oauth2_adapter = get_identity_oauth2_adapter(
            request,
            social_app=social_app,
            callback_url=redirect_uri,
        )
        client = oauth2_adapter.get_client(request, social_app)
        apple_post = getattr(request, 'shellui_apple_oauth_post', None)
        if isinstance(apple_post, dict):
            original_get_token = oauth2_adapter.get_access_token_data

            def _get_access_token_data(req, app, oauth_client, pkce_code_verifier=None):  # noqa: ANN001
                data = original_get_token(
                    req,
                    app,
                    oauth_client,
                    pkce_code_verifier=pkce_code_verifier,
                )
                if apple_post.get('user'):
                    data['user'] = apple_post['user']
                return data

            oauth2_adapter.get_access_token_data = _get_access_token_data
        access_token_data = oauth2_adapter.get_access_token_data(
            request,
            social_app,
            client,
            pkce_code_verifier=pkce_code_verifier,
        )
        token = oauth2_adapter.parse_token(access_token_data)
        try:
            sociallogin = oauth2_adapter.complete_login(
                request,
                social_app,
                token,
                response=access_token_data,
            )
        except KeyError as exc:
            # Userinfo omitted `sub`. Keep the token response so the caller can
            # verify the id_token and reject with oauth_subject_mismatch.
            if exc.args != ('sub',):
                raise
            sociallogin = None
        return sociallogin, access_token_data


def sociallogin_userinfo(sociallogin) -> dict[str, Any]:
    account = sociallogin.account
    extra = account.extra_data if isinstance(account.extra_data, dict) else {}
    nested = extra.get('userinfo') if isinstance(extra.get('userinfo'), dict) else {}
    data = dict(nested) if nested else dict(extra)
    if sociallogin.user.email and 'email' not in data:
        data['email'] = sociallogin.user.email
    if sociallogin.user.get_full_name() and 'name' not in data:
        data['name'] = sociallogin.user.get_full_name()
    if account.uid:
        data['_allauth_account_uid'] = account.uid
    if isinstance(extra.get('id_token'), dict):
        data['_verified_id_token_claims'] = extra['id_token']
    state = getattr(sociallogin, 'state', None)
    if isinstance(state, dict) and isinstance(state.get('id_token'), dict):
        data['_verified_id_token_claims'] = state['id_token']
    return data


def catalog_entry_from_client(social_app: SocialApp):
    return catalog_entry_for_social_app(social_app)
