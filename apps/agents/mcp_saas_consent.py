"""Optional SaaS access at MCP consent (global identity sign-in, then regional agent)."""

from __future__ import annotations

import hashlib
import logging
import secrets
from base64 import urlsafe_b64encode
from urllib.parse import urlencode

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect

from apps.agents.mcp_signin import _issuer, render_error
from apps.agents.exchange import agent_exchange_enabled
from apps.federation.relying import _upstream_configured

logger = logging.getLogger(__name__)

MCP_SAAS_OFFERED_KEY = 'mcp_oauth_saas_offered'
MCP_SAAS_GLOBAL_VERIFIED_KEY = 'mcp_saas_global_verified'
MCP_PENDING_CONSENT_KEY = 'mcp_pending_consent'
SAAS_RETURN_PATH = '/oauth/mcp/saas-return'
_STATE_TTL = 600


def saas_return_url(request: HttpRequest | None = None) -> str:
    base = _issuer()
    if not base and request is not None:
        base = request.build_absolute_uri('/').rstrip('/')
    return f'{base}{SAAS_RETURN_PATH}' if base else ''


def is_mcp_saas_return_redirect(url: str | None) -> bool:
    target = str(url or '').strip()
    expected = saas_return_url()
    return bool(target and expected and target == expected)


def saas_opt_in_offered(request: HttpRequest) -> bool:
    if not bool(str(getattr(settings, 'SAAS_SERVICE_URL', '') or '').strip()):
        return False
    return bool(request.session.get(MCP_SAAS_OFFERED_KEY))


def remember_saas_offered_from_params(request: HttpRequest, params) -> None:
    from apps.agents.mcp_signin import saas_offered_in_params

    offered = saas_offered_in_params(params)
    if not offered and request.method == 'POST':
        offered = saas_offered_in_params(request.GET)
    if offered:
        remember_saas_offered(request, offered=True)
    elif request.method == 'GET':
        remember_saas_offered(request, offered=False)


def remember_saas_offered(request: HttpRequest, *, offered: bool) -> None:
    if offered:
        request.session[MCP_SAAS_OFFERED_KEY] = True
    else:
        request.session.pop(MCP_SAAS_OFFERED_KEY, None)


def saas_opt_in_requires_global_signin(*, include_saas: bool, request: HttpRequest) -> bool:
    if not include_saas or not saas_opt_in_offered(request):
        return False
    if not agent_exchange_enabled():
        return False
    return not request.session.get(MCP_SAAS_GLOBAL_VERIFIED_KEY)


def store_pending_consent(request: HttpRequest, payload: dict) -> None:
    request.session[MCP_PENDING_CONSENT_KEY] = payload


def pop_pending_consent(request: HttpRequest) -> dict | None:
    raw = request.session.pop(MCP_PENDING_CONSENT_KEY, None)
    return raw if isinstance(raw, dict) else None


def start_global_identity_signin(
    request: HttpRequest,
    *,
    company_id: int,
) -> HttpResponseRedirect | HttpResponse:
    """Interactive upstream OAuth (never silent). User must sign in on global identity."""
    if not _upstream_configured():
        return render_error(request, 'invalid_request', 400)
    verifier = secrets.token_urlsafe(48)
    challenge = urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    redirect_uri = saas_return_url(request)
    cache.set(
        f'mcp:saas-upstream:{state}',
        {
            'nonce': nonce,
            'verifier': verifier,
            'company_id': company_id,
            'redirect_uri': redirect_uri,
        },
        timeout=_STATE_TTL,
    )
    params = {
        'response_type': 'code',
        'client_id': settings.GLOBAL_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'scope': 'openid email profile',
        'state': state,
        'nonce': nonce,
        'prompt': 'login',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    }
    location = f'{settings.GLOBAL_ISSUER_URL.rstrip("/")}/oauth/authorize?{urlencode(params)}'
    return HttpResponseRedirect(location)
