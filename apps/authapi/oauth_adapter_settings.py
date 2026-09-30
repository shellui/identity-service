"""Apply per-company SocialApp.settings to allauth OAuth2 adapter instances."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.openid_connect.views import OpenIDConnectOAuth2Adapter

from apps.authapi.oauth_safe_http import assert_public_http_url, safe_get_json
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
) -> None:
    cls = adapter.__class__
    adapter.__class__ = type(
        f'Shellui{cls.__name__}',
        (cls,),
        {
            'authorize_url': property(lambda self, url=authorize_url: url),
            'access_token_url': property(lambda self, url=access_token_url: url),
            'profile_url': property(lambda self, url=profile_url: url),
        },
    )


def prefetch_openid_connect_config(adapter: OpenIDConnectOAuth2Adapter) -> None:
    if hasattr(adapter, '_openid_config'):
        return
    server_url = adapter.get_provider().server_url
    assert_public_http_url(server_url)
    from apps.authapi.oauth_safe_http import validate_oidc_discovery_document

    document = safe_get_json(server_url)
    validate_oidc_discovery_document(document)
    adapter._openid_config = document


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
        prefetch_openid_connect_config(adapter)
        return

    if slug == 'auth0':
        base = str(settings.get('AUTH0_URL') or '').strip().rstrip('/')
        if base:
            adapter.provider_base_url = base
            adapter.access_token_url = f'{base}/oauth/token'
            adapter.authorize_url = f'{base}/authorize'
            adapter.profile_url = f'{base}/userinfo'
        return

    if slug == 'okta':
        base = str(settings.get('OKTA_BASE_URL') or '').strip().rstrip('/')
        if base:
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
