"""Provider-shaped HTTP mocks and fixtures for real allauth adapter e2e tests."""

from __future__ import annotations

import contextlib
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers import registry
from allauth.socialaccount.providers.oauth2.views import OAuth2Adapter
from django.test import RequestFactory

from apps.authapi.provider_registry import ProviderCatalogEntry, get_provider_catalog
from apps.authapi.tests.oauth_ssrf_test_utils import pin_oauth_http_to_localhost
from apps.authapi.tests.oauth_test_crypto import (
    AppleTestSigningKey,
    OAuthMockHttpsServer,
    OAuthTestSigningKey,
    generate_apple_test_signing_key,
    generate_oauth_test_signing_key,
    json_response_handler,
)

PUBLIC_HOST = 'https://example.com'
_PROFILE_FIXTURES_PATH = (
    Path(__file__).resolve().parents[3] / 'tools' / 'data' / 'oauth_e2e_profile_fixtures.json'
)

PROFILE_SEED_OVERRIDES: dict[str, dict[str, Any]] = {
    'apple': {
        'sub': 'uid-apple',
        'email': 'user-apple@example.com',
        'email_verified': True,
        'name': {'firstName': 'User', 'lastName': 'Apple'},
    },
    'slack': {
        'ok': True,
        'team': {'id': 'T-SLACK', 'name': 'Slack Team'},
        'user': {
            'id': 'U-SLACK',
            'name': 'User Slack',
            'email': 'user-slack@example.com',
        },
        'email': 'user-slack@example.com',
        'email_verified': True,
    },
    'shopify': {
        'shop': {
            'id': 12345,
            'email': 'user-shopify@example.com',
            'name': 'Test Shop',
            'myshopify_domain': 'test-shop.myshopify.com',
        }
    },
    'nextcloud': {
        'id': 'uid-nextcloud',
        'displayname': 'User Nextcloud',
        'email': 'user-nextcloud@example.com',
    },
    'salesforce': {
        'sub': 'uid-salesforce',
        'user_id': 'uid-salesforce',
        'email': 'user-salesforce@example.com',
        'email_verified': True,
        'name': 'User Salesforce',
    },
    'dropbox': {
        'account_id': 'uid-dropbox',
        'email': 'user-dropbox@example.com',
        'name': {'display_name': 'User Dropbox'},
    },
    'notion': {
        'access_token': 'access-notion',
        'token_type': 'bearer',
        'bot_id': 'bot-notion',
        'workspace_id': 'ws-notion',
        'workspace_name': 'Notion Workspace',
        'workspace_icon': None,
        'owner': {
            'user': {
                'id': 'user-notion',
                'name': 'User Notion',
                'avatar_url': None,
                'person': {'email': 'user-notion@example.com'},
            }
        },
    },
    'basecamp': {
        'identity': {
            'id': 4242,
            'email_address': 'user-basecamp@example.com',
            'first_name': 'User',
            'last_name': 'Basecamp',
        }
    },
    'microsoft': {
        'id': 'uid-microsoft',
        'mail': 'user-microsoft@example.com',
        'userPrincipalName': 'user-microsoft@example.com',
        'displayName': 'User Microsoft',
    },
    'github': {
        'id': 1,
        'login': 'user-github',
        'email': 'user-github@example.com',
        'name': 'User GitHub',
    },
}


def _load_profile_seed(slug: str) -> dict[str, Any]:
    if slug in PROFILE_SEED_OVERRIDES:
        return dict(PROFILE_SEED_OVERRIDES[slug])
    try:
        catalog = json.loads(_PROFILE_FIXTURES_PATH.read_text(encoding='utf-8'))
        if slug in catalog:
            return dict(catalog[slug])
    except OSError:
        pass
    return {}


def build_profile_for_provider(request, slug: str, social_app: SocialApp) -> dict:
    seed = _load_profile_seed(slug)
    if seed:
        entry = get_provider_catalog().by_slug()[slug]
        provider = registry.get_class(entry.allauth_id)(request, app=social_app)
        try:
            provider.extract_uid(seed)
            provider.extract_common_fields(seed)
            return seed
        except (KeyError, TypeError, AttributeError):
            if slug in PROFILE_SEED_OVERRIDES:
                raise

    entry = get_provider_catalog().by_slug()[slug]
    provider = registry.get_class(entry.allauth_id)(request, app=social_app)
    seed = {
        'sub': f'uid-{slug}',
        'id': f'uid-{slug}',
        'user_id': f'uid-{slug}',
        'email': f'user-{slug}@example.com',
        'email_verified': True,
        'verified': True,
        'is_email_verified': True,
        'name': f'User {slug}',
        'login': f'user-{slug}',
        'username': f'user-{slug}',
    }
    if slug == 'ynab':
        seed['data'] = {'user': {'id': f'uid-{slug}'}}
    for _ in range(80):
        try:
            provider.extract_uid(seed)
            provider.extract_common_fields(seed)
            return seed
        except KeyError as exc:
            key = exc.args[0]
            if not isinstance(key, str):
                raise
            low = key.lower()
            if 'email' in low:
                seed[key] = f'user-{slug}@example.com'
            elif low.endswith('id') or low in {'sub', 'uid', 'zuid'}:
                seed[key] = f'uid-{slug}'
            elif 'name' in low:
                seed[key] = f'User {slug}'
            else:
                seed[key] = 'value'
        except TypeError:
            if slug == 'ynab':
                seed.setdefault('data', {'user': {'id': f'uid-{slug}'}})
            else:
                raise
    raise AssertionError(f'Could not build a profile fixture for provider {slug!r}')


class ProviderOAuthHttpRouter:
    """Provider-aware JSON responses (token, profile, JWKS, discovery)."""

    def __init__(
        self,
        *,
        slug: str,
        profile: dict,
        discovery: dict | None,
        social_app: SocialApp,
        signing_key: OAuthTestSigningKey,
        apple_signing_key: AppleTestSigningKey | None = None,
    ):
        self.slug = slug
        self.profile = profile
        self.discovery = discovery or {}
        self.social_app = social_app
        self.signing_key = signing_key
        self.apple_signing_key = apple_signing_key

    def request(self, method, url, **kwargs):  # noqa: ANN001
        parsed = urlparse(str(url))
        path = parsed.path or '/'
        if path.endswith('openid-configuration') or path.endswith('.well-known/openid-configuration'):
            return _json_response(self.discovery or {})
        if (
            'oauth/access_token' in path
            or path.endswith('/token')
            or 'access_token' in path
            or 'openid.connect.token' in path
        ):
            return _json_response(self._token_body())
        if 'keys' in path or 'jwks' in path or path.endswith('/certs'):
            if self.slug == 'apple' and self.apple_signing_key is not None:
                return _json_response(self.apple_signing_key.jwks_document())
            if self.slug == 'google':
                return _json_response(self.signing_key.google_certs_document())
            return _json_response(self.signing_key.jwks_document())
        if 'api.github.com' in parsed.netloc:
            if path.endswith('/user/emails'):
                return _json_response(
                    [
                        {
                            'email': self.profile.get('email'),
                            'primary': True,
                            'verified': True,
                        }
                    ]
                )
            return _json_response(self.profile)
        if 'slack.com' in parsed.netloc and 'userInfo' in path:
            return _json_response({**self.profile, 'ok': True})
        if 'shop.json' in path:
            return _json_response(self.profile if 'shop' in self.profile else {'shop': self.profile})
        if self.slug == 'nextcloud' and '/ocs/' in path:
            return _json_response({'ocs': {'data': self.profile}})
        if 'userinfo' in path or '/user' in path or '/me' in path or '/profile' in path:
            return _json_response(self._profile_payload())
        if str(method).upper() == 'GET':
            return _json_response(self._profile_payload())
        return _json_response({'access_token': f'access-{self.slug}', 'token_type': 'Bearer'})

    def _profile_payload(self) -> dict | list:
        if self.slug == 'basecamp' and 'identity' in self.profile:
            return self.profile
        if self.slug == 'notion':
            return self.profile
        return self.profile

    def _token_body(self) -> dict:
        if self.slug == 'notion':
            body = dict(self.profile)
            body.setdefault('access_token', f'access-{self.slug}')
            body.setdefault('token_type', 'bearer')
            return body
        body: dict[str, Any] = {
            'access_token': f'access-{self.slug}',
            'token_type': 'Bearer',
        }
        if self.slug == 'nextcloud':
            body['user_id'] = self.profile.get('id') or 'uid-nextcloud'
        if self._should_include_id_token():
            body['id_token'] = self._signed_id_token()
        return body

    def _should_include_id_token(self) -> bool:
        if self.slug in {'google', 'microsoft', 'apple', 'yahoo'}:
            return True
        if self.discovery and self.slug not in {'notion', 'dropbox', 'basecamp'}:
            return True
        return False

    def _signed_id_token(self) -> str:
        if self.slug in {'google', 'microsoft', 'apple', 'yahoo'}:
            issuer = self._default_issuer()
        else:
            issuer = self.discovery.get('issuer') or self._default_issuer()
        claims = {
            'iss': issuer,
            'sub': str(
                self.profile.get('sub')
                or self.profile.get('id')
                or self.profile.get('account_id')
                or f'uid-{self.slug}'
            ),
            'aud': self.social_app.client_id,
            'exp': int(time.time()) + 3600,
            'iat': int(time.time()),
            'email': self.profile.get('email') or f'user-{self.slug}@example.com',
            'email_verified': True,
        }
        if self.slug == 'microsoft':
            claims['tid'] = 'contoso.onmicrosoft.com'
        if self.slug == 'apple' and self.apple_signing_key is not None:
            claims['iss'] = 'https://appleid.apple.com'
            return self.apple_signing_key.sign_es256(claims)
        return self.signing_key.sign_rs256(claims)

    def _default_issuer(self) -> str:
        if self.slug == 'google':
            return 'https://accounts.google.com'
        if self.slug == 'microsoft':
            return 'https://login.microsoftonline.com/common/v2.0'
        if self.slug == 'apple':
            return 'https://appleid.apple.com'
        return f'{PUBLIC_HOST}/{self.slug}'


def _json_response(data: dict | list, *, status: int = 200):
    import requests

    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(data).encode()
    response.headers['Content-Type'] = 'application/json'
    return response


def _http_handler_from_router(router: ProviderOAuthHttpRouter):
    def _handle(http) -> None:
        host = (http.headers.get('Host') or 'example.com').split(':')[0]
        url = f'https://{host}{http.path}'
        length = int(http.headers.get('Content-Length') or '0')
        body = http.rfile.read(length) if length else None
        response = router.request(http.command, url, data=body)
        payload = response.content or b'{}'
        http.send_response(response.status_code)
        http.send_header('Content-Type', response.headers.get('Content-Type', 'application/json'))
        http.send_header('Content-Length', str(len(payload)))
        http.end_headers()
        http.wfile.write(payload)

    return _handle


def _coerce_url(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _host_from_url(url: str) -> str:
    return (urlparse(url).hostname or '').lower()


def _discover_provider_hosts(entry: ProviderCatalogEntry) -> set[str]:
    import importlib

    hosts: set[str] = set()
    for suffix in ('views', 'provider', 'constants'):
        module_name = f'allauth.socialaccount.providers.{entry.allauth_id}.{suffix}'
        try:
            mod = importlib.import_module(module_name)
        except ImportError:
            continue
        for val in vars(mod).values():
            if isinstance(val, str) and val.startswith(('http://', 'https://')):
                host = _host_from_url(val)
                if host:
                    hosts.add(host)
        for name in dir(mod):
            obj = getattr(mod, name)
            if isinstance(obj, type) and issubclass(obj, OAuth2Adapter):
                for attr in (
                    'access_token_url',
                    'profile_url',
                    'authorize_url',
                    'identity_url',
                    'public_key_url',
                ):
                    url = _coerce_url(getattr(obj, attr, None))
                    if url:
                        host = _host_from_url(url)
                        if host:
                            hosts.add(host)
    return hosts


def _hosts_from_settings(settings: dict) -> set[str]:
    hosts: set[str] = set()
    for raw in settings.values():
        if isinstance(raw, str) and raw.startswith(('http://', 'https://')):
            host = _host_from_url(raw)
            if host:
                hosts.add(host)
    return hosts


def _instance_adapter_hosts(
    entry: ProviderCatalogEntry,
    social_app: SocialApp,
    request,
) -> set[str]:
    if entry.allauth_id == 'openid_connect':
        return set()
    from apps.authapi.oauth_adapter_settings import apply_oauth_adapter_settings
    from apps.authapi.oauth_social_account import bind_oauth_social_app

    try:
        from allauth.core import context as allauth_context

        bind_oauth_social_app(request, social_app)
        allauth_context.request = request
        provider = registry.get_class(entry.allauth_id)(request, app=social_app)
        adapter = provider.get_oauth2_adapter(request)
        apply_oauth_adapter_settings(adapter, social_app=social_app, entry=entry)
        hosts: set[str] = set()
        for attr in (
            'access_token_url',
            'profile_url',
            'authorize_url',
            'identity_url',
            'public_key_url',
        ):
            url = _coerce_url(getattr(adapter, attr, None))
            if url:
                host = _host_from_url(url)
                if host:
                    hosts.add(host)
        return hosts
    except Exception:
        return set()


def _collect_mock_hostnames(
    *,
    entry: ProviderCatalogEntry,
    social_app: SocialApp,
    discovery: dict | None,
    request,
) -> set[str]:
    hosts = {
        'example.com',
        *_discover_provider_hosts(entry),
        *_instance_adapter_hosts(entry, social_app, request),
    }
    settings_data = social_app.settings if isinstance(social_app.settings, dict) else {}
    hosts.update(_hosts_from_settings(settings_data))
    if entry.docs_slug == 'microsoft':
        hosts.update({'login.microsoftonline.com', 'graph.microsoft.com'})
    if discovery:
        for key in (
            'issuer',
            'authorization_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
            'jwks_uri',
        ):
            raw = discovery.get(key)
            if isinstance(raw, str) and raw.startswith(('http://', 'https://')):
                host = _host_from_url(raw)
                if host:
                    hosts.add(host)
    return hosts


@contextlib.contextmanager
def oauth_provider_http_mock(
    *,
    slug: str,
    request,
    social_app: SocialApp,
    profile: dict,
    discovery: dict | None = None,
):
    """Exercise real pinned HTTP against a local TLS mock (signed id_tokens, JWKS)."""
    from unittest import mock

    entry = get_provider_catalog().by_slug()[slug]
    signing_key = generate_oauth_test_signing_key()
    apple_signing_key = generate_apple_test_signing_key() if slug == 'apple' else None
    router = ProviderOAuthHttpRouter(
        slug=slug,
        profile=profile,
        discovery=discovery,
        social_app=social_app,
        signing_key=signing_key,
        apple_signing_key=apple_signing_key,
    )
    handler = _http_handler_from_router(router)
    hostnames = sorted(
        _collect_mock_hostnames(
            entry=entry,
            social_app=social_app,
            discovery=discovery,
            request=request,
        )
    )
    routes = {}
    for host in hostnames:
        routes[(host, 'GET', '/')] = handler
        routes[(host, 'POST', '/')] = handler
    server = OAuthMockHttpsServer.start(hostnames=hostnames, routes=routes)
    host_ports = [(host, server.port) for host in hostnames]
    ssl_patch = mock.patch(
        'apps.actions.webhook_transport.ssl.create_default_context',
        return_value=server.ssl_client_context(),
    )
    try:
        with ssl_patch, pin_oauth_http_to_localhost(*host_ports):
            yield server
    finally:
        server.shutdown()


def discovery_document_for_slug(slug: str, *, issuer: str | None = None) -> dict:
    iss = issuer or f'{PUBLIC_HOST}/{slug}'
    base = iss.rstrip('/')
    return {
        'issuer': iss,
        'authorization_endpoint': f'{base}/authorize',
        'token_endpoint': f'{base}/token',
        'userinfo_endpoint': f'{base}/userinfo',
        'jwks_uri': f'{base}/jwks',
        'token_endpoint_auth_methods_supported': ['client_secret_post', 'client_secret_basic'],
    }


def authorize_get_path(slug: str) -> str:
    if slug == 'shopify':
        return '/api/v1/authorize?shop=test-shop.myshopify.com'
    return '/api/v1/authorize'


def _ephemeral_apple_audit_certificate_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def prepare_social_app_for_audit(slug: str, app: SocialApp) -> None:
    settings_data = dict(app.settings or {})
    if slug == 'salesforce':
        app.key = 'https://login.salesforce.com'
        app.save(update_fields=['key'])
    if slug == 'apple':
        app.key = 'APPLE-TEAM-ID'
        settings_data['certificate_key'] = _ephemeral_apple_audit_certificate_key()
        app.settings = settings_data
        app.save(update_fields=['key', 'settings'])
