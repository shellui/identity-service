"""Return URL after global identity sign-in for MCP SaaS opt-in."""

from __future__ import annotations

import logging

import requests
from django.views.decorators.http import require_GET

from apps.agents.mcp_saas_consent import (
    MCP_SAAS_GLOBAL_VERIFIED_KEY,
    pop_pending_consent,
    saas_return_url,
)
from apps.agents.mcp_copy import copy_for
from apps.agents.mcp_signin import page_language, render_error, render_message
from apps.agents.staff import is_mcp_oauth_refused_user
from apps.companies.models import Company
from apps.federation.relying import _exchange, link_verified_user
from apps.federation.signing import TokenError, verify_pinned
from django.conf import settings
from django.contrib.auth import login
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.views.decorators.clickjacking import xframe_options_deny

from apps.agents.mcp_signin import SESSION_BACKEND, is_company_member

logger = logging.getLogger(__name__)


@xframe_options_deny
@require_GET
def mcp_saas_return(request: HttpRequest) -> HttpResponse:
    from apps.federation.relying import _upstream_configured

    if not _upstream_configured():
        return render_error(request, 'invalid_request', 404)
    pending = pop_pending_consent(request)
    if not pending:
        copy = copy_for(page_language(request))
        return render_message(request, copy['start_again'], 400)
    state = (request.GET.get('state') or '').strip()
    saved = cache.get(f'mcp:saas-upstream:{state}') if state else None
    if not isinstance(saved, dict):
        return render_error(request, 'invalid_request', 400)
    cache.delete(f'mcp:saas-upstream:{state}')
    company = Company.objects.filter(pk=saved.get('company_id')).first()
    if company is None:
        return render_error(request, 'invalid_request', 400)
    if (request.GET.get('error') or '').strip():
        return render_error(request, 'invalid_request', 400)
    code = (request.GET.get('code') or '').strip()
    if not code:
        return render_error(request, 'invalid_request', 400)
    if saved.get('redirect_uri') != saas_return_url(request):
        return render_error(request, 'invalid_request', 400)
    try:
        id_token = _exchange(code, saved)
        claims = verify_pinned(
            id_token,
            audience=settings.GLOBAL_CLIENT_ID,
            issuer_url=settings.GLOBAL_ISSUER_URL,
            require=['exp', 'iat', 'iss', 'aud', 'sub', 'nonce', 'email'],
        )
    except (TokenError, requests.RequestException, ValueError):
        logger.info('mcp_saas_return token rejected company_id=%s', company.pk)
        return render_error(request, 'invalid_request', 400)
    if claims.get('nonce') != saved.get('nonce'):
        return render_error(request, 'invalid_request', 400)
    if claims.get('email_verified') is not True:
        return render_error(request, 'invalid_request', 400)
    user, link_error = link_verified_user(claims)
    if link_error or user is None:
        return render_error(request, 'invalid_request', 400)
    if is_mcp_oauth_refused_user(user) or not is_company_member(company, user):
        copy = copy_for(page_language(request, user))
        return render_message(request, copy['not_member'].format(company=company.name), 403, user=user)
    login(request, user, backend=SESSION_BACKEND)
    request.session[MCP_SAAS_GLOBAL_VERIFIED_KEY] = True
    if pending.get('device_grant_id'):
        from apps.agents.oauth_device import complete_pending_device_consent

        return complete_pending_device_consent(request, user=user, company=company, pending=pending)
    from apps.agents.oauth_views import complete_pending_mcp_consent

    return complete_pending_mcp_consent(request, user=user, company=company, pending=pending)
