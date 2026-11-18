"""OpenID Provider endpoints. Served only when the instance role is global."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from urllib.parse import unquote, urlencode, urlsplit, urlunsplit

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.federation.http import FederationView

from apps.federation import codes
from apps.federation.events import emit_authorize_succeeded
from apps.federation.role import is_global
from apps.federation.session import email_is_verified, read_session
from apps.federation.signing import issuer, sign_rs256, unix_now

_ID_TOKEN_TTL = 300


def _disabled():
    return Response(status=404)


class OpenIdConfigurationView(FederationView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        if not is_global():
            return _disabled()
        base = _public_issuer(request)
        return Response(
            {
                'issuer': base,
                'authorization_endpoint': f'{base}/oauth/authorize',
                'token_endpoint': f'{base}/oauth/token',
                'userinfo_endpoint': f'{base}/oauth/userinfo',
                'jwks_uri': f'{base}/.well-known/jwks.json',
                'scopes_supported': ['openid', 'email', 'profile'],
                'response_types_supported': ['code'],
                'grant_types_supported': ['authorization_code'],
                'subject_types_supported': ['public'],
                'id_token_signing_alg_values_supported': ['RS256'],
                'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
                'claims_supported': [
                    'sub',
                    'iss',
                    'aud',
                    'exp',
                    'iat',
                    'nonce',
                    'auth_time',
                    'email',
                    'email_verified',
                    'name',
                ],
                'prompt_values_supported': _prompt_values(),
                'backchannel_logout_supported': True,
                'backchannel_logout_session_supported': True,
                'code_challenge_methods_supported': ['S256'],
            }
        )


# Path ai-service global registers on identity-global (IDENTITY_GLOBAL_OIDC_CLIENTS).
SHELLUI_ACCOUNT_REDIRECT_PATH = '/oauth/mcp/signin/complete'


def client_requires_shellui_account(client: dict | None) -> bool:
    """True for the ai-global sign-in client.

    The dev stack registers that client with redirect URIs ending in
    ``/oauth/mcp/signin/complete`` and no extra field. ``shellui_account_required``
    JSON true also marks a client.
    """
    if not isinstance(client, dict):
        return False
    if client.get('shellui_account_required') is True:
        return True
    for uri in client.get('redirect_uris') or []:
        path = urlsplit(str(uri)).path.rstrip('/') or '/'
        if path == SHELLUI_ACCOUNT_REDIRECT_PATH:
            return True
    return False


@dataclass(frozen=True)
class AuthorizeSpec:
    client: dict
    redirect_uri: str
    state: str
    nonce: str
    challenge: str
    prompt: str

    @property
    def shellui_account_required(self) -> bool:
        return client_requires_shellui_account(self.client)


class AuthorizeView(FederationView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        loaded = load_authorize_request(request)
        if not isinstance(loaded, AuthorizeSpec):
            return loaded
        return render_authorize(request, loaded)


def load_authorize_request(request) -> AuthorizeSpec | HttpResponse:
    """Validate an authorize query. Errors are redirects, or 400 when the client is unknown."""
    if not is_global():
        return HttpResponse(status=404)
    client = _client(request.GET.get('client_id'))
    redirect_uri = (request.GET.get('redirect_uri') or '').strip()
    if client is None or redirect_uri not in client['redirect_uris']:
        return JsonResponse({'error': 'invalid_client'}, status=400)
    state = request.GET.get('state') or ''
    prompt = (request.GET.get('prompt') or '').strip()
    if request.GET.get('response_type') != 'code':
        return _redirect_error(redirect_uri, 'unsupported_response_type', state)
    scope = (request.GET.get('scope') or '').split()
    if 'openid' not in scope:
        return _redirect_error(redirect_uri, 'invalid_scope', state)
    nonce = (request.GET.get('nonce') or '').strip()
    if not nonce or not state:
        return _redirect_error(redirect_uri, 'invalid_request', state)
    challenge = (request.GET.get('code_challenge') or '').strip()
    method = (request.GET.get('code_challenge_method') or '').strip()
    interactive = client_requires_shellui_account(client)
    if challenge and method != 'S256':
        return _redirect_error(redirect_uri, 'invalid_request', state)
    if not interactive and prompt != 'none':
        return _redirect_error(redirect_uri, 'interaction_required', state)
    if interactive and prompt not in {'', 'none', 'login'}:
        return _redirect_error(redirect_uri, 'interaction_required', state)
    return AuthorizeSpec(
        client=client,
        redirect_uri=redirect_uri,
        state=state,
        nonce=nonce,
        challenge=challenge,
        prompt=prompt,
    )


def render_authorize(request, spec: AuthorizeSpec) -> HttpResponse:
    """Silent clients stay on ``prompt=none``. A Shellui-account client can show a login page."""
    from apps.agents.staff import is_mcp_oauth_refused_user
    from apps.federation.oidc_login import render_login_page, render_staff_refused

    session = read_session(request)
    if spec.prompt == 'none':
        if session is None:
            return _redirect_error(spec.redirect_uri, 'login_required', spec.state)
        user, sid = session
        if spec.shellui_account_required and is_mcp_oauth_refused_user(user):
            return _redirect_error(
                spec.redirect_uri,
                'access_denied',
                spec.state,
                description='Staff accounts cannot authorize this client.',
            )
        return issue_authorization_redirect(spec, user, sid)
    if spec.prompt != 'login' and session is not None:
        user, _sid = session
        if is_mcp_oauth_refused_user(user):
            return render_staff_refused(request, spec)
        return render_login_page(request, spec, signed_in=user)
    return render_login_page(request, spec, signed_in=None)


def issue_authorization_redirect(spec: AuthorizeSpec, user, sid: str, response: HttpResponse | None = None):
    code = codes.store_code(
        {
            'user_id': user.pk,
            'client_id': spec.client['client_id'],
            'redirect_uri': spec.redirect_uri,
            'nonce': spec.nonce,
            'sid': sid,
            'code_challenge': spec.challenge,
            'auth_time': unix_now(),
        }
    )
    emit_authorize_succeeded(user=user, client_id=spec.client['client_id'])
    target = _with_query(spec.redirect_uri, {'code': code, 'state': spec.state})
    if response is None:
        return HttpResponseRedirect(target)
    response['Location'] = target
    response.status_code = 302
    return response


def _prompt_values() -> list[str]:
    values = ['none']
    clients = getattr(settings, 'OIDC_CLIENTS', []) or []
    if any(client_requires_shellui_account(client) for client in clients):
        values.append('login')
    return values


class TokenView(FederationView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        from apps.federation.exchange import GRANT_TYPE, handle_token_exchange

        if request.data.get('grant_type') == GRANT_TYPE:
            return handle_token_exchange(request)
        if not is_global():
            return _disabled()
        client_id, secret = _client_credentials(request)
        client = _client(client_id)
        if client is None or not _same_secret(secret, client['client_secret']):
            return Response({'error': 'invalid_client'}, status=401)
        if request.data.get('grant_type') != 'authorization_code':
            return Response({'error': 'unsupported_grant_type'}, status=400)
        payload = codes.consume_code(str(request.data.get('code') or ''))
        if payload is None or payload.get('client_id') != client['client_id']:
            return Response({'error': 'invalid_grant'}, status=400)
        if (request.data.get('redirect_uri') or '') != payload.get('redirect_uri'):
            return Response({'error': 'invalid_grant'}, status=400)
        if not _pkce_ok(payload.get('code_challenge') or '', str(request.data.get('code_verifier') or '')):
            return Response({'error': 'invalid_grant'}, status=400)
        from django.contrib.auth import get_user_model

        user = get_user_model().objects.filter(pk=payload['user_id'], is_active=True).first()
        if user is None:
            return Response({'error': 'invalid_grant'}, status=400)
        try:
            id_token = _id_token(user, client_id=client['client_id'], payload=payload)
        except Exception:
            return Response({'error': 'server_error'}, status=500)
        access = codes.store_access_token({'user_id': user.pk, 'client_id': client['client_id']})
        return Response(
            {
                'access_token': access,
                'token_type': 'Bearer',
                'expires_in': int(getattr(settings, 'OIDC_CODE_TTL_SECONDS', 60)),
                'id_token': id_token,
                'scope': 'openid email profile',
            }
        )


class UserInfoView(FederationView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        return self._userinfo(request)

    def post(self, request):
        return self._userinfo(request)

    def _userinfo(self, request):
        if not is_global():
            return _disabled()
        header = request.headers.get('Authorization', '')
        if not header.lower().startswith('bearer '):
            return Response({'error': 'invalid_token'}, status=401)
        payload = codes.read_access_token(header.split(' ', 1)[1].strip())
        if payload is None:
            return Response({'error': 'invalid_token'}, status=401)
        from django.contrib.auth import get_user_model

        user = get_user_model().objects.filter(pk=payload['user_id'], is_active=True).first()
        if user is None:
            return Response({'error': 'invalid_token'}, status=401)
        return Response(_profile(user))


def _id_token(user, *, client_id: str, payload: dict) -> str:
    now = unix_now()
    claims = {
        'iss': _configured_issuer(),
        'sub': str(user.pk),
        'aud': client_id,
        'exp': now + int(getattr(settings, 'OIDC_ID_TOKEN_TTL_SECONDS', _ID_TOKEN_TTL)),
        'iat': now,
        'auth_time': int(payload.get('auth_time') or now),
        'nonce': payload['nonce'],
        'sid': payload.get('sid') or '',
        'email': user.email or '',
        'email_verified': email_is_verified(user),
    }
    name = (user.get_full_name() or '').strip()
    if name:
        claims['name'] = name
    return sign_rs256(claims)


def _profile(user) -> dict:
    body = {
        'sub': str(user.pk),
        'email': user.email or '',
        'email_verified': email_is_verified(user),
    }
    name = (user.get_full_name() or '').strip()
    if name:
        body['name'] = name
    return body


def _configured_issuer() -> str:
    value = issuer()
    if not value:
        raise RuntimeError('JWT_ISSUER is not set.')
    return value


def _public_issuer(request) -> str:
    value = issuer()
    if value:
        return value
    return request.build_absolute_uri('/').rstrip('/')


def _client(client_id: str | None) -> dict | None:
    wanted = (client_id or '').strip()
    if not wanted:
        return None
    for client in getattr(settings, 'OIDC_CLIENTS', []) or []:
        if client.get('client_id') == wanted:
            return client
    return None


def _client_credentials(request) -> tuple[str, str]:
    header = request.headers.get('Authorization', '')
    if header.lower().startswith('basic '):
        try:
            decoded = base64.b64decode(header.split(' ', 1)[1].strip(), validate=True).decode('utf-8')
            client_id, secret = decoded.split(':', 1)
            return unquote(client_id), unquote(secret)
        except (ValueError, UnicodeDecodeError):
            return '', ''
    data = request.data if isinstance(request.data, dict) else {}
    return str(data.get('client_id') or ''), str(data.get('client_secret') or '')


def _pkce_ok(challenge: str, verifier: str) -> bool:
    if not challenge:
        return True
    if not verifier:
        return False
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    import base64 as b64

    computed = b64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return _same_secret(computed, challenge)


def _same_secret(presented: str, expected: str) -> bool:
    if not presented or not expected or len(presented) != len(expected):
        return False
    return hmac.compare_digest(presented, expected)


def _redirect_error(redirect_uri: str, error: str, state: str, description: str = ''):
    params = {'error': error}
    if description:
        params['error_description'] = description
    if state:
        params['state'] = state
    return HttpResponseRedirect(_with_query(redirect_uri, params))


def _with_query(url: str, params: dict) -> str:
    parts = urlsplit(url)
    query = urlencode(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ''))
