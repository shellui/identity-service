"""HTTP mocks and profile fixtures for real allauth adapter tests (no complete_login stubs)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers import registry
from django.test import RequestFactory

from apps.authapi.provider_registry import get_provider_catalog

PUBLIC_HOST = 'https://example.com'

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
}


def build_profile_for_provider(request, slug: str, social_app: SocialApp) -> dict:
    if slug in PROFILE_SEED_OVERRIDES:
        seed = dict(PROFILE_SEED_OVERRIDES[slug])
        entry = get_provider_catalog().by_slug()[slug]
        provider = registry.get_class(entry.allauth_id)(request, app=social_app)
        provider.extract_uid(seed)
        provider.extract_common_fields(seed)
        return seed

    entry = get_provider_catalog().by_slug()[slug]
    provider = registry.get_class(entry.allauth_id)(request, app=social_app)
    seed: dict[str, Any] = {
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


class MockOAuthHttpRouter:
    """Route OAuth HTTP calls to deterministic JSON fixtures per provider slug."""

    def __init__(self, *, slug: str, profile: dict, discovery: dict | None = None):
        self.slug = slug
        self.profile = profile
        self.discovery = discovery or {}

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
            return _json_response(self.profile)
        if 'keys' in path or 'jwks' in path:
            return _json_response({'keys': []})
        if str(method).upper() == 'GET':
            return _json_response(self.profile)
        return _json_response({'access_token': f'access-{self.slug}', 'token_type': 'Bearer'})

    def _token_body(self) -> dict:
        body: dict[str, Any] = {
            'access_token': f'access-{self.slug}',
            'token_type': 'Bearer',
            'id_token': self._unsigned_id_token(),
        }
        if self.slug == 'nextcloud':
            body['user_id'] = self.profile.get('id') or 'uid-nextcloud'
        return body

    def _unsigned_id_token(self) -> str:
        import base64

        issuer = self.discovery.get('issuer', f'{PUBLIC_HOST}/{self.slug}')
        payload_data: dict[str, Any] = {
            'sub': self.profile.get('sub') or self.profile.get('id') or f'uid-{self.slug}',
            'email': self.profile.get('email') or f'user-{self.slug}@example.com',
            'email_verified': True,
            'iss': issuer,
        }
        if self.slug == 'microsoft':
            payload_data['tid'] = 'contoso.onmicrosoft.com'
        header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip('=')
        return f'{header}.{payload}.'


def _json_response(data: dict | list, *, status: int = 200):
    import requests

    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(data).encode()
    response.headers['Content-Type'] = 'application/json'
    return response


def patch_verified_id_token_decode():
    """Allow unsigned test id_tokens to exercise adapter parse_token paths."""
    import contextlib

    import jwt

    @contextlib.contextmanager
    def _ctx():
        from unittest import mock

        def _decode(*, credential, **kwargs):
            return jwt.decode(
                credential,
                options={'verify_signature': False},
                algorithms=['none', 'HS256', 'RS256'],
            )

        with mock.patch(
            'allauth.socialaccount.internal.jwtkit.verify_and_decode',
            side_effect=_decode,
        ):
            yield

    return _ctx()


def patch_oauth_http(slug: str, profile: dict, discovery: dict | None = None):
    router = MockOAuthHttpRouter(slug=slug, profile=profile, discovery=discovery)

    class _Session:
        def request(self, method, url, **kwargs):
            return router.request(method, url, **kwargs)

        def get(self, url, **kwargs):
            return self.request('GET', url, **kwargs)

        def post(self, url, **kwargs):
            return self.request('POST', url, **kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    return _Session()


def discovery_document_for_slug(slug: str) -> dict:
    return {
        'issuer': f'{PUBLIC_HOST}/{slug}',
        'authorization_endpoint': f'{PUBLIC_HOST}/{slug}/authorize',
        'token_endpoint': f'{PUBLIC_HOST}/{slug}/token',
        'userinfo_endpoint': f'{PUBLIC_HOST}/{slug}/userinfo',
        'jwks_uri': f'{PUBLIC_HOST}/{slug}/jwks',
    }


def authorize_get_path(slug: str) -> str:
    if slug == 'shopify':
        return '/api/v1/authorize?shop=test-shop.myshopify.com'
    return '/api/v1/authorize'


def _ephemeral_apple_audit_certificate_key() -> str:
    """Generate a throwaway EC key for Apple OAuth client_secret JWT in tests (not committed)."""
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
