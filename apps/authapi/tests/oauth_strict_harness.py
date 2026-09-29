"""Strict OAuth adapter tests: exact HTTP routes, real JWT verification, no catch-all mocks."""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers import registry
from django.test import RequestFactory

from apps.authapi.oauth import build_authorize_url, resolve_oauth_client
from apps.authapi.oauth_allauth import exchange_allauth_code
from allauth.core import context as allauth_context

from apps.authapi.oauth_request_context import oauth_allauth_request
from apps.authapi.oauth_social_account import bind_oauth_social_app
from apps.authapi.provider_registry import get_provider_catalog
from apps.authapi.tests.oauth_ssrf_test_utils import pin_oauth_http_to_localhost
from apps.authapi.tests.oauth_test_crypto import (
    AppleTestSigningKey,
    OAuthMockHttpsServer,
    OAuthTestSigningKey,
    generate_apple_test_signing_key,
    generate_oauth_test_signing_key,
    json_response_handler,
)

RouteHandler = Callable[[BaseHTTPRequestHandler], None]


@dataclass
class StrictProviderSpec:
    slug: str
    authorize_netloc: str
    routes: dict[tuple[str, str, str], RouteHandler]
    hostnames: list[str]
    profile_field: str
    profile_value: str
    shop_param: str | None = None


def _route_key(url: str, *, method: str = 'GET') -> tuple[str, str, str]:
    parsed = urlparse(url)
    host = (parsed.hostname or '').lower()
    path = parsed.path or '/'
    return host, method.upper(), path


def _token_json_handler(payload: dict) -> RouteHandler:
    body = json.dumps(payload).encode()

    def _handler(http: BaseHTTPRequestHandler) -> None:
        from apps.authapi.tests.oauth_test_crypto import _drain_request_body

        _drain_request_body(http)
        http.send_response(200)
        http.send_header('Content-Type', 'application/json')
        http.end_headers()
        http.wfile.write(body)

    return _handler


def _json_handler(payload: dict | Callable[[], dict]) -> RouteHandler:
    def _handler(http: BaseHTTPRequestHandler) -> None:
        data = payload() if callable(payload) else payload
        body = json.dumps(data).encode()
        http.send_response(200)
        http.send_header('Content-Type', 'application/json')
        http.end_headers()
        http.wfile.write(body)

    return _handler


def build_strict_spec(
    *,
    slug: str,
    request,
    social_app: SocialApp,
    signing: OAuthTestSigningKey | None = None,
    apple_signing: AppleTestSigningKey | None = None,
) -> StrictProviderSpec:
    entry = get_provider_catalog().by_slug()[slug]
    bind_oauth_social_app(request, social_app)
    with oauth_allauth_request(request, social_app=social_app), allauth_context.request_context(request):
        provider = registry.get_class(entry.allauth_id)(request, app=social_app)
        adapter_class = getattr(provider, 'oauth2_adapter_class', None)
        if adapter_class is None:
            raise ValueError(f'provider {slug} has no oauth2_adapter_class')
        if entry.allauth_id == 'openid_connect':
            adapter = adapter_class(request, provider_id=social_app.provider_id or slug)
        else:
            adapter = adapter_class(request)
        authorize_url = adapter.authorize_url
        access_token_url = adapter.access_token_url
        profile_url = getattr(adapter, 'profile_url', None) or getattr(adapter, 'userinfo_url', None) or getattr(
            adapter, 'identity_url', None
        )
        emails_url = getattr(adapter, 'emails_url', None)
        token_method = getattr(adapter, 'access_token_method', 'POST') or 'POST'
        return _build_strict_spec_from_adapter(
            slug=slug,
            entry=entry,
            adapter=adapter,
            social_app=social_app,
            signing=signing,
            apple_signing=apple_signing,
            authorize_url=authorize_url,
            access_token_url=access_token_url,
            profile_url=profile_url,
            emails_url=emails_url,
            token_method=token_method,
        )


def _build_strict_spec_from_adapter(
    *,
    slug: str,
    entry,
    adapter,
    social_app: SocialApp,
    signing: OAuthTestSigningKey | None,
    apple_signing: AppleTestSigningKey | None,
    authorize_url: str,
    access_token_url: str,
    profile_url: str | None,
    emails_url: str | None,
    token_method: str,
) -> StrictProviderSpec:
    routes: dict[tuple[str, str, str], RouteHandler] = {}
    hostnames: set[str] = set()
    profile_field = 'sub'
    profile_value = f'uid-{slug}'
    shop_param: str | None = None

    authorize_netloc = (urlparse(authorize_url).hostname or '').lower()
    hostnames.add(authorize_netloc)

    token_key = _route_key(access_token_url, method=token_method)
    hostnames.add(token_key[0])

    client_id = social_app.client_id
    now = int(time.time())

    if slug == 'google':
        signing = signing or generate_oauth_test_signing_key(kid=f'{slug}-kid')
        id_token = signing.sign_rs256(
            {
                'iss': 'https://accounts.google.com',
                'aud': client_id,
                'sub': profile_value,
                'email': f'user-{slug}@example.com',
                'email_verified': True,
                'exp': now + 3600,
                'iat': now,
            }
        )
        routes[token_key] = _token_json_handler(
            {'access_token': 'at-google', 'token_type': 'Bearer', 'id_token': id_token}
        )
        certs_host = 'www.googleapis.com'
        hostnames.add(certs_host)
        routes[(certs_host, 'GET', '/oauth2/v3/certs')] = json_response_handler(
            signing.google_certs_document()
        )
        profile_field = 'sub'
    elif slug == 'github':
        routes[token_key] = _token_json_handler({'access_token': 'gh-token', 'token_type': 'bearer'})
        profile_key = _route_key(profile_url or '')
        hostnames.add(profile_key[0])
        routes[profile_key] = _json_handler(
            {
                'id': 12345,
                'login': f'user-{slug}',
                'name': f'User {slug}',
                'email': f'user-{slug}@example.com',
            }
        )
        profile_field = 'login'
        profile_value = f'user-{slug}'
        emails_key = _route_key(emails_url or '')
        if emails_key[0]:
            hostnames.add(emails_key[0])
            routes[emails_key] = _json_handler(
                [
                    {
                        'email': f'user-{slug}@example.com',
                        'primary': True,
                        'verified': True,
                    }
                ]
            )
    elif slug == 'microsoft':
        signing = signing or generate_oauth_test_signing_key(kid=f'{slug}-kid')
        tenant = str((social_app.settings or {}).get('tenant') or 'common')
        tid = '11111111-1111-1111-1111-111111111111'
        issuer = f'https://login.microsoftonline.com/{tid}/v2.0'
        id_token = signing.sign_rs256(
            {
                'iss': issuer,
                'aud': client_id,
                'sub': profile_value,
                'tid': tid,
                'xms_edov': True,
                'exp': now + 3600,
                'iat': now,
            }
        )
        routes[token_key] = _token_json_handler(
            {'access_token': 'ms-token', 'token_type': 'Bearer', 'id_token': id_token}
        )
        jwks_host = 'login.microsoftonline.com'
        hostnames.add(jwks_host)
        routes[(jwks_host, 'GET', '/common/discovery/v2.0/keys')] = json_response_handler(
            signing.jwks_document()
        )
        me_key = _route_key(profile_url or '')
        hostnames.add(me_key[0])
        routes[me_key] = _json_handler(
            {
                'id': profile_value,
                'mail': f'user-{slug}@example.com',
                'userPrincipalName': f'user-{slug}@example.com',
            }
        )
        profile_field = 'id'
    elif slug == 'apple':
        apple_signing = apple_signing or generate_apple_test_signing_key()
        nonce = 'strict-apple-nonce'
        id_token = apple_signing.sign_es256(
            {
                'iss': 'https://appleid.apple.com',
                'aud': client_id,
                'sub': profile_value,
                'nonce': nonce,
                'email': f'user-{slug}@example.com',
                'exp': now + 3600,
                'iat': now,
            }
        )
        routes[token_key] = _token_json_handler(
            {
                'access_token': 'apple-at',
                'token_type': 'Bearer',
                'expires_in': 3600,
                'id_token': id_token,
            }
        )
        keys_host = 'appleid.apple.com'
        hostnames.add(keys_host)
        routes[(keys_host, 'GET', '/auth/keys')] = json_response_handler(apple_signing.jwks_document())
        profile_field = 'sub'
    elif slug == 'shopify':
        shop = 'test-shop.myshopify.com'
        shop_param = shop
        routes[token_key] = _token_json_handler({'access_token': 'shopify-token'})
        profile_key = _route_key(profile_url or '')
        hostnames.add(profile_key[0])
        routes[profile_key] = _json_handler({'shop': {'id': 1, 'email': f'user-{slug}@example.com'}})
        profile_field = 'shop'
        profile_value = '1'
    else:
        profile_key = _route_key(profile_url) if profile_url else ('', 'GET', '/')
        if profile_key[0]:
            hostnames.add(profile_key[0])
        payload: dict[str, Any] = {
            'sub': profile_value,
            'id': profile_value,
            'email': f'user-{slug}@example.com',
            'email_verified': True,
            'login': profile_value,
            'name': f'User {slug}',
        }
        if slug == 'slack':
            payload = {
                'ok': True,
                'sub': profile_value,
                'email': f'user-{slug}@example.com',
                'https://slack.com/user_id': profile_value,
            }
        elif slug == 'discord':
            payload = {'id': profile_value, 'username': f'user-{slug}', 'email': f'user-{slug}@example.com'}
            profile_field = 'id'
        elif slug == 'dropbox':
            payload = {'account_id': profile_value, 'email': f'user-{slug}@example.com'}
            profile_field = 'account_id'
        elif slug == 'notion':
            payload = {
                'access_token': 'notion-at',
                'bot_id': profile_value,
                'owner': {'user': {'id': profile_value, 'email': f'user-{slug}@example.com'}},
            }
            profile_field = 'bot_id'
        elif slug == 'gitlab':
            payload = {'id': 99, 'username': profile_value, 'email': f'user-{slug}@example.com'}
            profile_field = 'username'
        elif slug == 'linkedin':
            payload = {'id': profile_value, 'localizedFirstName': 'User', 'localizedLastName': slug.title()}
            profile_field = 'id'
        elif slug == 'bitbucket':
            payload = {'uuid': profile_value, 'username': profile_value}
            profile_field = 'uuid'
        elif slug == 'facebook':
            graph_host = urlparse(profile_url or '').hostname or 'graph.facebook.com'
            hostnames.add(graph_host.lower())
            payload = {'id': profile_value, 'name': f'User {slug}', 'email': f'user-{slug}@example.com'}
            profile_field = 'id'
            routes[_route_key(f'https://{graph_host}{urlparse(profile_url or "").path}')] = _json_handler(
                payload
            )
        elif slug == 'zoom':
            payload = {'id': profile_value, 'email': f'user-{slug}@example.com'}
            profile_field = 'id'
        elif slug == 'atlassian':
            payload = {'account_id': profile_value, 'email': f'user-{slug}@example.com', 'name': f'User {slug}'}
            profile_field = 'account_id'
        elif slug == 'salesforce':
            payload = {'sub': profile_value, 'email': f'user-{slug}@example.com', 'email_verified': True}

        if slug in {'okta', 'auth0', 'keycloak'} or entry.allauth_id == 'openid_connect':
            signing = signing or generate_oauth_test_signing_key(kid=f'{slug}-kid')
            issuer_host = profile_key[0] or f'{slug}.example.com'
            issuer = f'https://{issuer_host}'
            id_token = signing.sign_rs256(
                {
                    'iss': issuer,
                    'aud': client_id,
                    'sub': profile_value,
                    'email': f'user-{slug}@example.com',
                    'email_verified': True,
                    'exp': now + 3600,
                    'iat': now,
                }
            )
            routes[token_key] = _token_json_handler(
                {'access_token': f'at-{slug}', 'id_token': id_token, 'token_type': 'Bearer'}
            )
            settings = social_app.settings or {}
            server_url = str(settings.get('server_url') or settings.get('OKTA_BASE_URL') or settings.get('AUTH0_URL') or '')
            doc_host = (urlparse(server_url).hostname or issuer_host).lower()
            hostnames.add(doc_host)
            discovery = {
                'issuer': issuer,
                'jwks_uri': f'https://{doc_host}/jwks',
                'token_endpoint': access_token_url,
                'userinfo_endpoint': profile_url or f'https://{doc_host}/userinfo',
            }
            routes[(doc_host, 'GET', '/.well-known/openid-configuration')] = json_response_handler(discovery)
            routes[(doc_host, 'GET', '/jwks')] = json_response_handler(signing.jwks_document())
        else:
            routes[token_key] = _token_json_handler({'access_token': f'at-{slug}', 'token_type': 'Bearer'})
        if profile_url:
            method = 'POST' if slug == 'dropbox' else 'GET'
            routes[_route_key(profile_url, method=method)] = _json_handler(payload)

    return StrictProviderSpec(
        slug=slug,
        authorize_netloc=authorize_netloc,
        routes=routes,
        hostnames=sorted(hostnames),
        profile_field=profile_field,
        profile_value=str(profile_value),
        shop_param=shop_param,
    )


@contextmanager
def strict_provider_http(spec: StrictProviderSpec):
    server = OAuthMockHttpsServer.start(hostnames=spec.hostnames, routes=spec.routes)
    host_ports = [(host, server.port) for host in spec.hostnames]
    ssl_patch = patch_ssl_for_server(server)
    try:
        with pin_oauth_http_to_localhost(*host_ports):
            with ssl_patch:
                yield server
    finally:
        server.shutdown()


def patch_ssl_for_server(server: OAuthMockHttpsServer):
    from unittest.mock import patch

    return patch(
        'apps.actions.webhook_transport.ssl.create_default_context',
        return_value=server.ssl_client_context(),
    )


def run_strict_provider_round_trip(
    *,
    slug: str,
    request,
    social_app: SocialApp,
    company_id: int,
) -> str | None:
    """Return None on success, or an error string."""
    try:
        spec = build_strict_spec(slug=slug, request=request, social_app=social_app)
    except Exception as exc:
        return f'spec: {exc}'
    with strict_provider_http(spec):
        parsed_authorize = urlparse(
            build_authorize_url(
                slug,
                redirect_uri='https://app.example/callback',
                state='state-token',
                request=request,
                company_id=company_id,
                require_supported=False,
            )
        )
        if (parsed_authorize.hostname or '').lower() != spec.authorize_netloc:
            return f'authorize host expected {spec.authorize_netloc}, got {parsed_authorize.hostname}'
        exchange_query = {'code': 'abc'}
        if spec.shop_param:
            exchange_query['shop'] = spec.shop_param
        exchange_request = RequestFactory().get('/api/v1/oauth/callback', exchange_query)
        exchange_request.session = {}
        try:
            login, _token_data = exchange_allauth_code(
                exchange_request,
                social_app=social_app,
                redirect_uri='https://app.example/callback',
            )
        except Exception as exc:
            return str(exc)
    uid = str(login.account.uid or '')
    extra = login.account.extra_data if isinstance(login.account.extra_data, dict) else {}
    if uid == spec.profile_value:
        return None
    if str(extra.get(spec.profile_field) or '') == spec.profile_value:
        return None
    return f'missing profile field {spec.profile_field!r} (uid={uid!r}, extra={extra!r})'
