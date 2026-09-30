import json
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any

from django.db.utils import OperationalError, ProgrammingError
from allauth.socialaccount.models import SocialApp

from apps.authapi.oauth_allauth import (
    build_allauth_authorize_url,
    exchange_allauth_code,
    get_identity_oauth2_adapter,
    sociallogin_userinfo,
)
from apps.authapi.oauth_request_context import oauth_allauth_request
from apps.authapi.oauth_social_account import bind_oauth_social_app
from apps.authapi.provider_registry import (
    ProviderCatalogEntry,
    catalog_entry_for_social_app,
    resolve_catalog_slug,
    supported_oauth_provider_slugs,
)
from apps.companies.models import CompanyOAuthClient

SUPPORTED_OAUTH_PROVIDERS = supported_oauth_provider_slugs()


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scope: str


@dataclass(frozen=True)
class OAuthTokenBundle:
    access_token: str
    id_token: str | None = None


@dataclass(frozen=True)
class ResolvedOAuthClient:
    provider: str
    catalog_entry: ProviderCatalogEntry
    client_id: str
    client_secret: str
    tenant: str | None = None
    company_oauth_client_id: int | None = None
    social_app_id: int | None = None


def _match_social_app_provider(entry: ProviderCatalogEntry, social_app: SocialApp) -> bool:
    provider = str(social_app.provider).strip().lower()
    if provider != entry.allauth_id.lower():
        return False
    if entry.allauth_id == 'openid_connect':
        settings_data = social_app.settings if isinstance(getattr(social_app, 'settings', None), dict) else {}
        catalog_slug = str(settings_data.get('catalog_slug') or '').strip().lower()
        if catalog_slug and catalog_slug == entry.docs_slug.lower():
            return True
        sub_id = str(getattr(social_app, 'provider_id', '') or '').strip().lower()
        expected = entry.social_app_provider_id().lower()
        return sub_id == expected
    return True


def _resolve_company_client(
    provider: str,
    company_id: int | None,
    company_oauth_client_id: int | None,
    *,
    require_supported: bool = True,
) -> ResolvedOAuthClient | None:
    entry = resolve_catalog_slug(provider)
    if not entry or (require_supported and not entry.supported):
        return None
    if not company_id:
        return None
    try:
        qs = (
            CompanyOAuthClient.objects.filter(
                company_id=company_id,
                is_active=True,
            )
            .exclude(social_app__client_id='')
            .exclude(social_app__secret='')
            .select_related('social_app')
        )
        if company_oauth_client_id is not None:
            row = qs.filter(pk=company_oauth_client_id).first()
            if not row or not _match_social_app_provider(entry, row.social_app):
                return None
        else:
            row = None
            for candidate in qs.order_by('id'):
                if _match_social_app_provider(entry, candidate.social_app):
                    row = candidate
                    break
    except (OperationalError, ProgrammingError):
        return None
    if not row:
        return None
    social_app_settings = getattr(row.social_app, 'settings', {}) or {}
    if not isinstance(social_app_settings, dict):
        social_app_settings = {}
    return ResolvedOAuthClient(
        provider=entry.docs_slug,
        catalog_entry=entry,
        client_id=str(row.social_app.client_id).strip(),
        client_secret=str(row.social_app.secret).strip(),
        tenant=str(social_app_settings.get('tenant', '')).strip() or None,
        company_oauth_client_id=row.id,
        social_app_id=row.social_app_id,
    )


def resolve_oauth_client(
    provider: str,
    *,
    company_id: int | None = None,
    company_oauth_client_id: int | None = None,
    require_supported: bool = True,
) -> ResolvedOAuthClient:
    selected = _resolve_company_client(
        provider,
        company_id,
        company_oauth_client_id,
        require_supported=require_supported,
    )
    if not selected:
        raise ValueError(
            f'No OAuth client configured for provider {provider!r} and company {company_id!r}.'
        )
    if not selected.client_id or not selected.client_secret:
        raise ValueError(f'OAuth client for provider {provider!r} is missing credentials.')
    return selected


def get_social_app_for_client(resolved: ResolvedOAuthClient) -> SocialApp:
    if resolved.social_app_id is None:
        raise ValueError('Missing social_app_id on resolved OAuth client.')
    return SocialApp.objects.get(pk=resolved.social_app_id)


def get_provider_config(
    provider: str,
    *,
    company_id: int | None = None,
    company_oauth_client_id: int | None = None,
) -> ProviderConfig:
    resolved = resolve_oauth_client(
        provider,
        company_id=company_id,
        company_oauth_client_id=company_oauth_client_id,
    )
    return ProviderConfig(
        name=resolved.provider,
        client_id=resolved.client_id,
        client_secret=resolved.client_secret,
        authorize_url='',
        token_url='',
        userinfo_url='',
        scope='',
    )


def build_authorize_url(
    provider: str,
    redirect_uri: str,
    state: str | None = None,
    *,
    request=None,
    company_id: int | None = None,
    company_oauth_client_id: int | None = None,
    switch_account: bool = False,
    pkce_params: dict | None = None,
    oauth_nonce: str | None = None,
    require_supported: bool = True,
) -> str:
    if request is None:
        raise ValueError('HTTP request is required to build provider authorize URLs.')
    resolved = resolve_oauth_client(
        provider,
        company_id=company_id,
        company_oauth_client_id=company_oauth_client_id,
        require_supported=require_supported,
    )
    social_app = get_social_app_for_client(resolved)
    bind_oauth_social_app(request, social_app)
    signed_state = state or str(uuid.uuid4())
    return build_allauth_authorize_url(
        request,
        entry=resolved.catalog_entry,
        social_app=social_app,
        redirect_uri=redirect_uri,
        state=signed_state,
        switch_account=switch_account,
        pkce_params=pkce_params,
        oauth_nonce=oauth_nonce,
    )


def exchange_code_for_token(
    provider: str,
    code: str,
    redirect_uri: str,
    *,
    request=None,
    company_id: int | None = None,
    company_oauth_client_id: int | None = None,
    pkce_code_verifier: str | None = None,
) -> OAuthTokenBundle:
    if request is None:
        raise ValueError('HTTP request is required for OAuth code exchange.')
    if code and not request.GET.get('code'):
        query = request.GET.copy()
        query['code'] = code
        request.GET = query
    resolved = resolve_oauth_client(
        provider,
        company_id=company_id,
        company_oauth_client_id=company_oauth_client_id,
    )
    social_app = get_social_app_for_client(resolved)
    _sociallogin, data = exchange_allauth_code(
        request,
        social_app=social_app,
        redirect_uri=redirect_uri,
        pkce_code_verifier=pkce_code_verifier,
    )
    access_token = data.get('access_token')
    if not access_token:
        raise ValueError('No access token returned by provider.')
    id_token = data.get('id_token')
    id_str = id_token.strip() if isinstance(id_token, str) and id_token.strip() else None
    return OAuthTokenBundle(access_token=str(access_token), id_token=id_str)


def fetch_provider_userinfo(
    provider: str,
    access_token: str,
    *,
    request=None,
    company_id: int | None = None,
    company_oauth_client_id: int | None = None,
    redirect_uri: str | None = None,
    id_token: str | None = None,
) -> dict:
    if request is None:
        raise ValueError('HTTP request is required to load provider profiles.')
    resolved = resolve_oauth_client(
        provider,
        company_id=company_id,
        company_oauth_client_id=company_oauth_client_id,
    )
    social_app = get_social_app_for_client(resolved)
    bind_oauth_social_app(request, social_app)
    with oauth_allauth_request(request, social_app=social_app):
        oauth2_adapter = get_identity_oauth2_adapter(
            request,
            social_app=social_app,
            callback_url=redirect_uri or '',
        )
        token_response: dict[str, Any] = {'access_token': access_token}
        if id_token:
            token_response['id_token'] = id_token
        token = oauth2_adapter.parse_token(token_response)
        try:
            sociallogin = oauth2_adapter.complete_login(
                request,
                social_app,
                token,
                response=token_response,
            )
        except KeyError as exc:
            if exc.args == ('sub',) and id_token:
                from apps.authapi.oauth_errors import OAuthSubjectMismatchError

                raise OAuthSubjectMismatchError(
                    'OAuth userinfo subject does not match the identity token.',
                ) from exc
            raise
        if sociallogin is None:
            if id_token:
                from apps.authapi.oauth_errors import OAuthSubjectMismatchError

                raise OAuthSubjectMismatchError(
                    'OAuth userinfo subject does not match the identity token.',
                )
            raise ValueError('OAuth provider did not return a user id.')
        return sociallogin_userinfo(sociallogin)


def complete_oauth_social_login(
    *,
    request,
    provider: str,
    redirect_uri: str,
    company_id: int,
    company_oauth_client_id: int | None,
    pkce_code_verifier: str | None = None,
):
    resolved = resolve_oauth_client(
        provider,
        company_id=company_id,
        company_oauth_client_id=company_oauth_client_id,
    )
    social_app = get_social_app_for_client(resolved)
    sociallogin, token_data = exchange_allauth_code(
        request,
        social_app=social_app,
        redirect_uri=redirect_uri,
        pkce_code_verifier=pkce_code_verifier,
    )
    if sociallogin is None:
        from apps.authapi.oauth_errors import OAuthSubjectMismatchError

        raise OAuthSubjectMismatchError(
            'OAuth userinfo subject does not match the identity token.',
        )
    userinfo = sociallogin_userinfo(sociallogin)
    access_token = str(token_data.get('access_token') or '')
    id_token = token_data.get('id_token')
    id_str = id_token.strip() if isinstance(id_token, str) and id_token.strip() else None
    token_bundle = OAuthTokenBundle(access_token=access_token, id_token=id_str)
    return sociallogin, token_bundle, userinfo, resolved


def oauth_skip_confirm_provider_ids() -> frozenset[str]:
    from django.conf import settings

    configured = getattr(settings, 'OAUTH_SKIP_CONFIRM_PROVIDERS', ())
    return frozenset(str(item).strip().lower() for item in configured if str(item).strip())


def oauth_identity_sufficient_for_auto_confirm(
    provider: str,
    *,
    email: str,
    userinfo: dict,
) -> bool:
    """True when profile data is safe to finalize login without the confirm step."""
    normalized_email = (email or '').strip().lower()
    if not normalized_email or '@' not in normalized_email:
        return False
    if normalized_email.endswith(f'@{provider}.local'):
        return False
    verified = userinfo.get('email_verified')
    if verified is False or verified == 'false':
        return False
    return True


def should_skip_oauth_confirm(provider: str, *, email: str, userinfo: dict) -> bool:
    key = str(provider).strip().lower()
    if key not in oauth_skip_confirm_provider_ids():
        return False
    return oauth_identity_sufficient_for_auto_confirm(key, email=email, userinfo=userinfo)


def social_app_catalog_slug(social_app: SocialApp) -> str:
    entry = catalog_entry_for_social_app(social_app)
    if entry is not None:
        return entry.docs_slug
    return str(social_app.provider).strip().lower()
