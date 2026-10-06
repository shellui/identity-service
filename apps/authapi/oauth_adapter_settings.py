"""Apply per-company SocialApp.settings to allauth OAuth2 adapter instances."""

from __future__ import annotations

import types

import jwt
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.openid_connect.views import OpenIDConnectOAuth2Adapter

from apps.authapi.oauth_errors import OAuthProviderConfigError
from apps.authapi.oauth_linkedin import LINKEDIN_OIDC_SERVER_URL, load_linkedin_oidc_discovery
from apps.authapi.oauth_twitch import (
    TWITCH_ACCESS_TOKEN_URL,
    TWITCH_AUTHORIZE_URL,
    TWITCH_PROFILE_URL,
)
from apps.authapi.oauth_oidc_discovery import (
    discovery_url_for_server_url,
    load_validated_oidc_discovery,
    oidc_issuer_for_server_url,
)
from apps.authapi.provider_registry import ProviderCatalogEntry


def _settings_dict(social_app: SocialApp) -> dict:
    raw = social_app.settings
    return dict(raw) if isinstance(raw, dict) else {}


def _bind_adapter_url_properties(
    adapter,
    *,
    authorize_url: str,
    access_token_url: str,
    profile_url: str,
    userinfo_url: str | None = None,
) -> None:
    cls = adapter.__class__
    userinfo = userinfo_url or profile_url
    adapter.__class__ = type(
        f'Shellui{cls.__name__}',
        (cls,),
        {
            'authorize_url': property(lambda self, url=authorize_url: url),
            'access_token_url': property(lambda self, url=access_token_url: url),
            'profile_url': property(lambda self, url=profile_url: url),
            'userinfo_url': property(lambda self, url=userinfo: url),
        },
    )


def _unverified_id_token_claims(self, app, id_token: str) -> dict:  # noqa: ANN001
    """Decode without allauth's JWKS or jti cache. Shellui verifies the token once later."""
    try:
        claims = jwt.decode(
            id_token,
            options={'verify_signature': False, 'verify_exp': False},
            algorithms=['RS256', 'RS384', 'RS512', 'PS256', 'ES256', 'HS256'],
        )
    except Exception as exc:
        raise OAuth2Error('Invalid id_token') from exc
    if not isinstance(claims, dict):
        raise OAuth2Error('Invalid id_token')
    return claims


def _auth0_complete_login(self, request, app, token, **kwargs):  # noqa: ANN001
    from allauth.socialaccount.adapter import get_adapter

    headers = {'Authorization': f'Bearer {token.token}'}
    with get_adapter().get_requests_session() as sess:
        response = sess.get(self.profile_url, headers=headers)
        response.raise_for_status()
        extra_data = response.json()
    return self.get_provider().sociallogin_from_response(request, extra_data)


def _gitlab_complete_login(self, request, app, token, **kwargs):  # noqa: ANN001
    from allauth.socialaccount.adapter import get_adapter

    headers = {'Authorization': f'Bearer {token.token}'}
    with get_adapter().get_requests_session() as sess:
        response = sess.get(self.profile_url, headers=headers)
    if response.status_code >= 400:
        raise OAuth2Error('Invalid data from GitLab API.')
    try:
        data = response.json()
    except ValueError as exc:
        raise OAuth2Error('Invalid JSON from GitLab API.') from exc
    if not isinstance(data, dict) or 'id' not in data:
        raise OAuth2Error('Invalid data from GitLab API.')
    return self.get_provider().sociallogin_from_response(request, data)


def prefetch_openid_connect_config(
    adapter: OpenIDConnectOAuth2Adapter,
    *,
    entry: ProviderCatalogEntry | None = None,
) -> None:
    """Load discovery once, bound to the configured issuer, before allauth reads any endpoint."""
    if entry is not None and entry.docs_slug == 'linkedin':
        adapter._openid_config = load_linkedin_oidc_discovery()
        return
    server_url = adapter.get_provider().server_url
    issuer = oidc_issuer_for_server_url(server_url)
    if not issuer:
        raise OAuthProviderConfigError(
            'OpenID Connect server_url must be the issuer URL or its /.well-known/openid-configuration URL.'
        )
    adapter._openid_config = load_validated_oidc_discovery(
        discovery_url=discovery_url_for_server_url(server_url),
        expected_issuer=issuer,
    )


def apply_oauth_adapter_settings(
    adapter,
    *,
    social_app: SocialApp,
    entry: ProviderCatalogEntry | None,
) -> None:
    """Mutate adapter instance URLs and clients from SocialApp.settings."""
    settings = _settings_dict(social_app)
    slug = entry.docs_slug if entry is not None else str(social_app.provider).lower()

    if isinstance(adapter, OpenIDConnectOAuth2Adapter):
        if entry is not None and entry.docs_slug == 'linkedin':
            provider = adapter.get_provider()
            provider.app.settings = {
                **_settings_dict(social_app),
                'server_url': LINKEDIN_OIDC_SERVER_URL,
            }
        prefetch_openid_connect_config(adapter, entry=entry)
        adapter._decode_id_token = types.MethodType(_unverified_id_token_claims, adapter)
        return

    if slug == 'twitch':
        _bind_adapter_url_properties(
            adapter,
            authorize_url=TWITCH_AUTHORIZE_URL,
            access_token_url=TWITCH_ACCESS_TOKEN_URL,
            profile_url=TWITCH_PROFILE_URL,
        )
        return

    if slug == 'google':
        adapter._decode_id_token = types.MethodType(_unverified_id_token_claims, adapter)

    if slug == 'auth0':
        base = str(settings.get('AUTH0_URL') or '').strip().rstrip('/')
        if not base:
            raise OAuth2Error('Missing Auth0 AUTH0_URL in company OAuth settings.')
        adapter.provider_base_url = base
        adapter.access_token_url = f'{base}/oauth/token'
        adapter.authorize_url = f'{base}/authorize'
        adapter.profile_url = f'{base}/userinfo'
        adapter.complete_login = types.MethodType(_auth0_complete_login, adapter)
        return

    if slug == 'okta':
        base = str(settings.get('OKTA_BASE_URL') or '').strip().rstrip('/')
        if not base:
            raise OAuth2Error('Missing Okta OKTA_BASE_URL in company OAuth settings.')
        _bind_adapter_url_properties(
            adapter,
            authorize_url=f'{base}/oauth2/v1/authorize',
            access_token_url=f'{base}/oauth2/v1/token',
            profile_url=f'{base}/oauth2/v1/userinfo',
        )
        return

    if slug == 'amazon_cognito':
        domain = str(settings.get('DOMAIN') or '').strip().rstrip('/')
        if domain:
            _bind_adapter_url_properties(
                adapter,
                authorize_url=f'{domain}/oauth2/authorize',
                access_token_url=f'{domain}/oauth2/token',
                profile_url=f'{domain}/oauth2/userInfo',
            )
        return

    if slug == 'gumroad':
        base = str(settings.get('GUMROAD_URL') or 'https://gumroad.com').strip().rstrip('/')
        adapter.access_token_url = f'{base}/oauth/token'
        adapter.authorize_url = f'{base}/oauth/authorize'
        adapter.profile_url = f'{base}/api/v2/user'

    if slug == 'jupyterhub':
        base = str(settings.get('API_URL') or '').strip().rstrip('/')
        if base:
            adapter.access_token_url = f'{base}/hub/api/oauth2/token'
            adapter.authorize_url = f'{base}/hub/api/oauth2/authorize'
            adapter.profile_url = f'{base}/hub/api/user'

    if slug == 'edx':
        base = str(settings.get('EDX_URL') or settings.get('API_URL') or '').strip().rstrip('/')
        if base:
            adapter.provider_base_url = base
            adapter.access_token_url = f'{base}/oauth2/access_token'
            adapter.authorize_url = f'{base}/oauth2/authorize/'
            adapter.profile_url = f'{base}/api/user/v1/me'

    if slug == 'mailcow':
        server = str(settings.get('SERVER') or settings.get('API_URL') or '').strip().rstrip('/')
        if server:
            adapter.server = server
            adapter.access_token_url = f'{server}/oauth/token'
            adapter.authorize_url = f'{server}/oauth/authorize'
            adapter.profile_url = f'{server}/oauth/profile'

    if slug == 'mediawiki':
        rest_api = str(settings.get('REST_API') or settings.get('MEDIAWIKI_URL') or '').strip().rstrip('/')
        if rest_api:
            adapter.REST_API = rest_api
            adapter.access_token_url = f'{rest_api}/oauth2/access_token'
            adapter.authorize_url = f'{rest_api}/oauth2/authorize'
            adapter.profile_url = f'{rest_api}/oauth2/resource/profile'

    if slug == 'gitea':
        web_url = str(settings.get('GITEA_URL') or settings.get('API_URL') or '').strip().rstrip('/')
        if web_url:
            adapter.api_url = f'{web_url}/api/v1'
            adapter.access_token_url = f'{web_url}/login/oauth/access_token'
            adapter.authorize_url = f'{web_url}/login/oauth/authorize'
            adapter.profile_url = f'{web_url}/api/v1/user'

    if slug == 'gitlab':
        base = str(settings.get('gitlab_url') or 'https://gitlab.com').strip().rstrip('/')
        _bind_adapter_url_properties(
            adapter,
            authorize_url=f'{base}/oauth/authorize',
            access_token_url=f'{base}/oauth/token',
            profile_url=f'{base}/api/v4/user',
        )
        adapter.complete_login = types.MethodType(_gitlab_complete_login, adapter)

    if slug == 'nextcloud':
        server = str(settings.get('server') or '').strip().rstrip('/')
        if server:
            adapter._server_override = server

    if slug == 'sharefile':
        subdomain = str(settings.get('SUBDOMAIN') or 'secure').strip()
        apicp = str(settings.get('APICP') or 'sharefile.com').strip()
        base = str(settings.get('API_URL') or settings.get('DEFAULT_URL') or '').strip().rstrip('/')
        if base:
            adapter.provider_default_url = base
        adapter.access_token_url = f'https://{subdomain}.{apicp}/oauth/token'
        adapter.authorize_url = f'https://{subdomain}.{apicp}/oauth/authorize'
        if base:
            adapter.profile_url = f'{base}/oauth/userinfo'

    if slug == 'lemonldap':
        base = str(settings.get('LEMONLDAP_URL') or '').strip().rstrip('/')
        if base:
            adapter.access_token_url = f'{base}/oauth2/token'
            adapter.authorize_url = f'{base}/oauth2/authorize'
            adapter.profile_url = f'{base}/oauth2/userinfo'

    if slug == 'netiq':
        base = str(settings.get('NETIQ_URL') or '').strip().rstrip('/')
        if base:
            _bind_adapter_url_properties(
                adapter,
                authorize_url=f'{base}/nidp/oauth/nam/authorize',
                access_token_url=f'{base}/nidp/oauth/nam/token',
                profile_url=f'{base}/nidp/oauth/nam/userinfo',
            )
