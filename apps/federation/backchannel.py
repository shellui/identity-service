"""Back-channel logout. The provider sends; the relying party revokes local sessions."""

from __future__ import annotations

import logging

import requests
from django.conf import settings
from django.core.cache import cache
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.federation.http import FederationView

from apps.authapi.refresh_sessions import revoke_all_refresh_sessions_for_user
from apps.federation.events import emit_backchannel_logout_sent
from apps.federation.models import UpstreamAccount
from apps.federation.role import is_global, is_region
from apps.federation.session import clear_session_ids, session_ids
from apps.federation.signing import TokenError, new_jti, sign_rs256, unix_now, verify_pinned

logger = logging.getLogger(__name__)

LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout'


def send_backchannel_logout(*, user) -> None:
    """Tell each configured client to end sessions for this user. No-op unless provider role."""
    if not is_global() or user is None:
        return
    sid = None
    stored = session_ids(user.pk)
    if stored:
        sid = stored[-1]
    timeout = float(getattr(settings, 'OIDC_BACKCHANNEL_TIMEOUT_SECONDS', 3))
    for client in getattr(settings, 'OIDC_CLIENTS', []) or []:
        uri = (client.get('backchannel_logout_uri') or '').strip()
        if not uri:
            continue
        token = _logout_token(user, client_id=client['client_id'], sid=sid)
        try:
            requests.post(
                uri,
                data={'logout_token': token},
                timeout=timeout,
                allow_redirects=False,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
        except requests.RequestException:
            logger.warning('backchannel logout failed client_id=%s', client.get('client_id'))
            continue
        emit_backchannel_logout_sent(user=user, client_id=client['client_id'])
    clear_session_ids(user.pk)


class BackchannelLogoutView(FederationView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        if not is_region():
            return Response(status=404)
        raw = request.data.get('logout_token') if isinstance(request.data, dict) else None
        if not isinstance(raw, str) or not raw.strip():
            raw = request.POST.get('logout_token')
        if not isinstance(raw, str) or not raw.strip():
            return Response({'error': 'invalid_request'}, status=400)
        try:
            claims = verify_pinned(
                raw.strip(),
                audience=settings.GLOBAL_CLIENT_ID,
                issuer_url=settings.GLOBAL_ISSUER_URL,
                require=['exp', 'iat', 'iss', 'aud', 'jti'],
            )
        except TokenError:
            return Response({'error': 'invalid_token'}, status=400)
        events = claims.get('events')
        if not isinstance(events, dict) or LOGOUT_EVENT not in events:
            return Response({'error': 'invalid_token'}, status=400)
        if claims.get('nonce') is not None:
            return Response({'error': 'invalid_token'}, status=400)
        sub = str(claims.get('sub') or '').strip()
        if not sub:
            return Response({'error': 'invalid_token'}, status=400)
        jti = str(claims['jti'])
        ttl = max(1, int(claims['exp']) - unix_now())
        if not cache.add(f'federation:logout-jti:{jti}', 1, timeout=ttl):
            return Response({'error': 'invalid_token'}, status=400)
        issuer = str(claims.get('iss') or '').rstrip('/')
        link = UpstreamAccount.objects.filter(issuer=issuer, sub=sub).select_related('user').first()
        if link is not None:
            revoke_all_refresh_sessions_for_user(link.user)
        return Response(status=200)


def _logout_token(user, *, client_id: str, sid: str | None) -> str:
    now = unix_now()
    claims = {
        'iss': (settings.JWT_ISSUER or '').rstrip('/'),
        'sub': str(user.pk),
        'aud': client_id,
        'iat': now,
        'exp': now + 60,
        'jti': new_jti(),
        'events': {LOGOUT_EVENT: {}},
    }
    if sid:
        claims['sid'] = sid
    return sign_rs256(claims)
