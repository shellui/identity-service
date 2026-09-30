"""Strict OAuth adapter tests (exact routes, literal uid constants, local JWKS for id_tokens)."""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from typing import Callable
from urllib.parse import urlparse

from allauth.core import context as allauth_context
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers import registry
from allauth.socialaccount.providers.openid_connect.views import OpenIDConnectOAuth2Adapter
from django.test import RequestFactory

from apps.authapi.oauth import build_authorize_url
from apps.authapi.oauth_adapter_settings import apply_oauth_adapter_settings
from apps.authapi.oauth_allauth import exchange_allauth_code
from apps.authapi.oauth_request_context import oauth_allauth_request
from apps.authapi.oauth_social_account import bind_oauth_social_app
from apps.authapi.provider_registry import get_provider_catalog
from apps.authapi.tests.oauth_oidc_strict_fixtures import (
    OidcCompanyFixture,
    company_auth0_base,
    company_generic_oidc,
    company_keycloak_oidc,
    company_linkedin_oidc,
    company_okta_base,
)
from apps.authapi.tests.oauth_supported_provider_fixtures import (
    RELEASE_SUPPORTED_OAUTH_SLUGS,
    company_gitlab_url,
    supported_provider_fixture,
)
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
    expected_uid: str
    shop_param: str | None = None
    company_host: str | None = None


def _route_key(url: str, *, method: str = 'GET') -> tuple[str, str, str]:
    parsed = urlparse(url)
    host = (parsed.hostname or '').lower()
    path = parsed.path or '/'
    return host, method.upper(), path


def _host_from_url(url: str | None) -> str | None:
    if not url:
        return None
    return (urlparse(url).hostname or '').lower() or None


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


def _json_handler(payload: dict) -> RouteHandler:
    body = json.dumps(payload).encode()

    def _handler(http: BaseHTTPRequestHandler) -> None:
        http.send_response(200)
        http.send_header('Content-Type', 'application/json')
        http.end_headers()
        http.wfile.write(body)

    return _handler


def _assert_adapter_hosts(
    *,
    slug: str,
    authorize_url: str,
    access_token_url: str,
    profile_url: str | None,
    company_host: str | None,
) -> None:
    auth_host = _host_from_url(authorize_url)
    token_host = _host_from_url(access_token_url)
    profile_host = _host_from_url(profile_url)
    if not auth_host or not token_host:
        raise ValueError(f'{slug}: authorize or token URL host is missing after adapter settings')
    company_scoped = {'gitlab', 'linkedin', 'keycloak', 'openid_connect', 'okta', 'auth0'}
    if slug in company_scoped:
        if not company_host:
            raise ValueError(f'{slug} requires company_host')
        for label, host in (
            ('authorize', auth_host),
            ('token', token_host),
            ('profile', profile_host),
        ):
            if host and host != company_host:
                raise ValueError(f'{slug} {label} host {host!r} != company host {company_host!r}')
        return
    expected: dict[str, set[str]] = {
        'apple': {'appleid.apple.com'},
        'github': {'github.com', 'api.github.com'},
        'google': {'accounts.google.com', 'oauth2.googleapis.com', 'www.googleapis.com'},
        'line': {'access.line.me', 'api.line.me'},
        'microsoft': {'login.microsoftonline.com', 'graph.microsoft.com'},
        'reddit': {'www.reddit.com', 'oauth.reddit.com', 'reddit.com'},
        'shopify': {'fixture-shop.myshopify.com'},
        'slack': {'slack.com'},
    }
    allowed = expected.get(slug)
    if allowed is None:
        return
    for label, host in (
        ('authorize', auth_host),
        ('token', token_host),
        ('profile', profile_host),
    ):
        if host and host not in allowed:
            raise ValueError(f'{slug} {label} host {host!r} not in allowed {sorted(allowed)}')


def _company_host_for_slug(slug: str, *, company_slug: str, social_app: SocialApp) -> str | None:
    if slug == 'gitlab':
        return urlparse(company_gitlab_url(company_slug)).hostname
    if slug == 'linkedin':
        return company_linkedin_oidc(company_slug).hostname
    if slug == 'keycloak':
        return company_keycloak_oidc(company_slug).hostname
    if slug == 'openid_connect':
        return company_generic_oidc(company_slug).hostname
    if slug == 'okta':
        return urlparse(company_okta_base(company_slug)).hostname
    if slug == 'auth0':
        return urlparse(company_auth0_base(company_slug)).hostname
    return None


def _oidc_fixture_for_slug(slug: str, company_slug: str) -> OidcCompanyFixture:
    if slug == 'linkedin':
        return company_linkedin_oidc(company_slug)
    if slug == 'keycloak':
        return company_keycloak_oidc(company_slug)
    if slug == 'openid_connect':
        return company_generic_oidc(company_slug)
    raise ValueError(f'provider {slug} is not an OpenID Connect catalog entry')


def _oidc_discovery_document(oidc: OidcCompanyFixture) -> dict[str, str]:
    issuer = oidc.issuer
    return {
        'issuer': issuer,
        'authorization_endpoint': f'{issuer}/authorize',
        'token_endpoint': f'{issuer}/token',
        'userinfo_endpoint': f'{issuer}/userinfo',
        'jwks_uri': f'{issuer}/jwks',
        'token_endpoint_auth_methods_supported': ['client_secret_post'],
    }


def _build_oidc_strict_spec(
    *,
    slug: str,
    company_slug: str,
    social_app: SocialApp,
    fixture_expected_uid: str,
    profile: dict,
    signing: OAuthTestSigningKey | None = None,
) -> StrictProviderSpec:
    oidc = _oidc_fixture_for_slug(slug, company_slug)
    discovery = _oidc_discovery_document(oidc)
    authorize_url = discovery['authorization_endpoint']
    access_token_url = discovery['token_endpoint']
    profile_url = discovery['userinfo_endpoint']
    company_host = oidc.hostname
    signing = signing or generate_oauth_test_signing_key(kid=f'{slug}-oidc-kid')
    client_id = social_app.client_id
    now = int(time.time())
    id_token = signing.sign_rs256(
        {
            'iss': discovery['issuer'],
            'aud': client_id,
            'sub': fixture_expected_uid,
            'email': profile.get('email'),
            'email_verified': True,
            'exp': now + 3600,
            'iat': now,
        }
    )
    routes: dict[tuple[str, str, str], RouteHandler] = {}
    hostnames: set[str] = {company_host}
    discovery_path = urlparse(oidc.server_url).path or '/.well-known/openid-configuration'
    routes[(company_host, 'GET', discovery_path)] = json_response_handler(discovery)
    jwks_path = urlparse(discovery['jwks_uri']).path or '/jwks'
    routes[(company_host, 'GET', jwks_path)] = json_response_handler(signing.jwks_document())
    token_key = _route_key(access_token_url, method='POST')
    routes[token_key] = _token_json_handler(
        {'access_token': f'at-{slug}', 'token_type': 'Bearer', 'id_token': id_token}
    )
    profile_key = _route_key(profile_url)
    routes[profile_key] = _json_handler(profile)
    authorize_netloc = (urlparse(authorize_url).hostname or '').lower()
    return StrictProviderSpec(
        slug=slug,
        authorize_netloc=authorize_netloc,
        routes=routes,
        hostnames=sorted(hostnames),
        expected_uid=fixture_expected_uid,
        company_host=company_host,
    )


def _assert_oidc_adapter_urls_with_live_discovery(
    *,
    slug: str,
    request,
    social_app: SocialApp,
    company_slug: str,
) -> None:
    entry = get_provider_catalog().by_slug()[slug]
    company_host = _company_host_for_slug(slug, company_slug=company_slug, social_app=social_app)
    bind_oauth_social_app(request, social_app)
    with oauth_allauth_request(request, social_app=social_app), allauth_context.request_context(request):
        adapter = OpenIDConnectOAuth2Adapter(request, social_app.provider_id)
        apply_oauth_adapter_settings(adapter, social_app=social_app, entry=entry)
        profile_url = adapter.profile_url
        _assert_adapter_hosts(
            slug=slug,
            authorize_url=adapter.authorize_url,
            access_token_url=adapter.access_token_url,
            profile_url=profile_url,
            company_host=company_host,
        )


def build_strict_spec(
    *,
    slug: str,
    request,
    social_app: SocialApp,
    company_slug: str,
    signing: OAuthTestSigningKey | None = None,
    apple_signing: AppleTestSigningKey | None = None,
) -> StrictProviderSpec:
    if slug not in RELEASE_SUPPORTED_OAUTH_SLUGS:
        raise ValueError(f'provider {slug} is not in the supported release set')
    fixture = supported_provider_fixture(slug)
    entry = get_provider_catalog().by_slug()[slug]
    profile = dict(fixture.profile_document)
    if entry.allauth_id == 'openid_connect':
        return _build_oidc_strict_spec(
            slug=slug,
            company_slug=company_slug,
            social_app=social_app,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            signing=signing,
        )
    bind_oauth_social_app(request, social_app)
    company_host = _company_host_for_slug(slug, company_slug=company_slug, social_app=social_app)

    with oauth_allauth_request(request, social_app=social_app), allauth_context.request_context(request):
        provider = registry.get_class(entry.allauth_id)(request, app=social_app)
        adapter_class = getattr(provider, 'oauth2_adapter_class', None)
        if adapter_class is None:
            raise ValueError(f'provider {slug} has no oauth2_adapter_class')
        adapter = adapter_class(request)
        apply_oauth_adapter_settings(adapter, social_app=social_app, entry=entry)
        authorize_url = adapter.authorize_url
        access_token_url = adapter.access_token_url
        profile_url = (
            getattr(adapter, 'profile_url', None)
            or getattr(adapter, 'userinfo_url', None)
            or getattr(adapter, 'identity_url', None)
        )
        emails_url = getattr(adapter, 'emails_url', None)
        token_method = getattr(adapter, 'access_token_method', 'POST') or 'POST'
        _assert_adapter_hosts(
            slug=slug,
            authorize_url=authorize_url,
            access_token_url=access_token_url,
            profile_url=profile_url,
            company_host=company_host,
        )
        return _build_routes_for_fixture(
            slug=slug,
            fixture_expected_uid=fixture.expected_uid,
            profile=profile,
            social_app=social_app,
            authorize_url=authorize_url,
            access_token_url=access_token_url,
            profile_url=profile_url,
            emails_url=emails_url,
            token_method=token_method,
            company_host=company_host,
            signing=signing,
            apple_signing=apple_signing,
        )


def _build_routes_for_fixture(
    *,
    slug: str,
    fixture_expected_uid: str,
    profile: dict,
    social_app: SocialApp,
    authorize_url: str,
    access_token_url: str,
    profile_url: str | None,
    emails_url: str | None,
    token_method: str,
    company_host: str | None,
    signing: OAuthTestSigningKey | None,
    apple_signing: AppleTestSigningKey | None,
) -> StrictProviderSpec:
    routes: dict[tuple[str, str, str], RouteHandler] = {}
    hostnames: set[str] = set()
    shop_param: str | None = None

    authorize_netloc = (urlparse(authorize_url).hostname or '').lower()
    if not authorize_netloc:
        raise ValueError(f'{slug}: authorize URL has no host')
    hostnames.add(authorize_netloc)

    token_key = _route_key(access_token_url, method=token_method)
    hostnames.add(token_key[0])

    client_id = social_app.client_id
    now = int(time.time())

    if slug == 'google':
        signing = signing or generate_oauth_test_signing_key(kid='google-kid')
        id_token = signing.sign_rs256(
            {
                'iss': 'https://accounts.google.com',
                'aud': client_id,
                'sub': fixture_expected_uid,
                'email': profile.get('email'),
                'email_verified': True,
                'exp': now + 3600,
                'iat': now,
            }
        )
        routes[token_key] = _token_json_handler(
            {'access_token': 'at-google', 'token_type': 'Bearer', 'id_token': id_token}
        )
        hostnames.add('www.googleapis.com')
        routes[('www.googleapis.com', 'GET', '/oauth2/v3/certs')] = json_response_handler(
            signing.google_certs_document()
        )
    elif slug == 'microsoft':
        signing = signing or generate_oauth_test_signing_key(kid='ms-kid')
        tid = str((social_app.settings or {}).get('tenant') or '11111111-1111-1111-1111-111111111111')
        issuer = f'https://login.microsoftonline.com/{tid}/v2.0'
        id_token = signing.sign_rs256(
            {
                'iss': issuer,
                'aud': client_id,
                'sub': 'ms-token-sub',
                'tid': tid,
                'xms_edov': True,
                'exp': now + 3600,
                'iat': now,
            }
        )
        routes[token_key] = _token_json_handler(
            {'access_token': 'ms-token', 'token_type': 'Bearer', 'id_token': id_token}
        )
        hostnames.add('login.microsoftonline.com')
        routes[('login.microsoftonline.com', 'GET', '/common/discovery/v2.0/keys')] = json_response_handler(
            signing.jwks_document()
        )
        me_key = _route_key(profile_url or '')
        hostnames.add(me_key[0])
        routes[me_key] = _json_handler(profile)
    elif slug == 'apple':
        apple_signing = apple_signing or generate_apple_test_signing_key()
        id_token = apple_signing.sign_es256(
            {
                'iss': 'https://appleid.apple.com',
                'aud': client_id,
                'sub': fixture_expected_uid,
                'nonce': 'strict-apple-nonce',
                'email': profile.get('email'),
                'exp': now + 3600,
                'iat': now,
            }
        )
        routes[token_key] = _token_json_handler(
            {'access_token': 'apple-at', 'token_type': 'Bearer', 'expires_in': 3600, 'id_token': id_token}
        )
        hostnames.add('appleid.apple.com')
        routes[('appleid.apple.com', 'GET', '/auth/keys')] = json_response_handler(apple_signing.jwks_document())
    elif slug == 'github':
        routes[token_key] = _token_json_handler({'access_token': 'gh-token', 'token_type': 'bearer'})
        profile_key = _route_key(profile_url or '')
        hostnames.add(profile_key[0])
        routes[profile_key] = _json_handler(profile)
        emails_key = _route_key(emails_url or '')
        if emails_key[0]:
            hostnames.add(emails_key[0])
            routes[emails_key] = _json_handler(
                [{'email': profile.get('email'), 'primary': True, 'verified': True}]
            )
    elif slug == 'shopify':
        shop_param = 'fixture-shop.myshopify.com'
        routes[token_key] = _token_json_handler({'access_token': 'shopify-token'})
        profile_key = _route_key(profile_url or '')
        hostnames.add(profile_key[0])
        routes[profile_key] = _json_handler(profile)
    elif slug == 'slack':
        routes[token_key] = _token_json_handler({'access_token': 'slack-openid-at', 'token_type': 'Bearer'})
        profile_key = _route_key(profile_url or '')
        hostnames.add(profile_key[0])
        routes[profile_key] = _json_handler(profile)
    else:
        routes[token_key] = _token_json_handler({'access_token': f'at-{slug}', 'token_type': 'Bearer'})
        if profile_url:
            profile_key = _route_key(profile_url)
            hostnames.add(profile_key[0])
            routes[profile_key] = _json_handler(profile)

    return StrictProviderSpec(
        slug=slug,
        authorize_netloc=authorize_netloc,
        routes=routes,
        hostnames=sorted(hostnames),
        expected_uid=fixture_expected_uid,
        shop_param=shop_param,
        company_host=company_host,
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
    company_slug: str,
) -> str | None:
    """Return None on success, or an error string."""
    try:
        spec = build_strict_spec(
            slug=slug,
            request=request,
            social_app=social_app,
            company_slug=company_slug,
        )
    except Exception as exc:
        return f'spec: {exc}'
    with strict_provider_http(spec):
        entry = get_provider_catalog().by_slug()[slug]
        if entry.allauth_id == 'openid_connect':
            try:
                _assert_oidc_adapter_urls_with_live_discovery(
                    slug=slug,
                    request=request,
                    social_app=social_app,
                    company_slug=company_slug,
                )
            except Exception as exc:
                return f'oidc adapter hosts: {exc}'
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
    if uid == spec.expected_uid:
        return None
    return f'uid mismatch expected {spec.expected_uid!r}, got {uid!r}'
