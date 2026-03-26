import json
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass

from django.conf import settings


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scope: str


def get_provider_config(provider: str) -> ProviderConfig:
    tenant = settings.SOCIALACCOUNT_PROVIDERS.get('microsoft', {}).get('TENANT', 'common')
    providers = {
        'github': ProviderConfig(
            name='github',
            client_id=settings.GITHUB_CLIENT_ID,
            client_secret=settings.GITHUB_CLIENT_SECRET,
            authorize_url='https://github.com/login/oauth/authorize',
            token_url='https://github.com/login/oauth/access_token',
            userinfo_url='https://api.github.com/user',
            scope='read:user user:email',
        ),
        'google': ProviderConfig(
            name='google',
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
            token_url='https://oauth2.googleapis.com/token',
            userinfo_url='https://www.googleapis.com/oauth2/v3/userinfo',
            scope='openid email profile',
        ),
        'microsoft': ProviderConfig(
            name='microsoft',
            client_id=settings.MICROSOFT_CLIENT_ID,
            client_secret=settings.MICROSOFT_CLIENT_SECRET,
            authorize_url=f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize',
            token_url=f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
            userinfo_url='https://graph.microsoft.com/v1.0/me',
            scope='openid email profile User.Read',
        ),
    }
    if provider not in providers:
        raise ValueError(f'Unsupported provider: {provider}')
    return providers[provider]


def build_authorize_url(provider: str, redirect_uri: str) -> str:
    config = get_provider_config(provider)
    params = {
        'client_id': config.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': config.scope,
        'state': str(uuid.uuid4()),
    }
    if provider == 'google':
        params['access_type'] = 'offline'
        params['prompt'] = 'consent'
    return f"{config.authorize_url}?{urllib.parse.urlencode(params)}"


def exchange_code_for_token(provider: str, code: str, redirect_uri: str) -> str:
    config = get_provider_config(provider)
    payload = {
        'client_id': config.client_id,
        'client_secret': config.client_secret,
        'code': code,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    }
    encoded = urllib.parse.urlencode(payload).encode('utf-8')
    req = urllib.request.Request(
        config.token_url,
        data=encoded,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        data = json.loads(response.read().decode('utf-8'))
    access_token = data.get('access_token')
    if not access_token:
        raise ValueError('No access token returned by provider.')
    return access_token


def fetch_provider_userinfo(provider: str, access_token: str) -> dict:
    config = get_provider_config(provider)
    req = urllib.request.Request(
        config.userinfo_url,
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        data = json.loads(response.read().decode('utf-8'))
    return data
