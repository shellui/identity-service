"""Silent sign-in against one trusted upstream provider. No login-page button."""

from __future__ import annotations

import hashlib
import logging
import secrets
from base64 import urlsafe_b64encode
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.http import HttpResponseRedirect
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.federation.http import FederationView

from apps.authapi.desktop_return import client_redirect_reports_success, client_redirect_response
from apps.authapi.oauth_user import normalize_oauth_email
from apps.companies.access import apply_company_join
from apps.companies.models import Company
from apps.companies.redirect_allowlist import append_oauth_error_params, validate_redirect_to_for_company
from apps.federation.models import UpstreamAccount
from apps.federation.role import is_region
from apps.federation.signing import TokenError, verify_pinned
from apps.federation.users import create_unprivileged_user

logger = logging.getLogger(__name__)
User = get_user_model()
PROVIDER = 'upstream'
_STATE_TTL = 600


def _disabled():
    return Response(status=404)


class SilentSignInView(FederationView):
    """Start prompt=none. Not linked from the company sign-in page."""

    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        if not is_region() or not _upstream_configured():
            return _disabled()
        company, redirect_to, error = _company_redirect(request)
        if error:
            return error
        verifier = secrets.token_urlsafe(48)
        challenge = urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        cache.set(
            f'federation:rp-state:{state}',
            {
                'nonce': nonce,
                'verifier': verifier,
                'company_id': company.id,
                'redirect_to': redirect_to,
                'redirect_uri': _redirect_uri(request),
                'shell_challenge': (request.GET.get('code_challenge') or '').strip(),
            },
            timeout=_STATE_TTL,
        )
        params = {
            'response_type': 'code',
            'client_id': settings.GLOBAL_CLIENT_ID,
            'redirect_uri': _redirect_uri(request),
            'scope': 'openid email profile',
            'state': state,
            'nonce': nonce,
            'prompt': 'none',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
        }
        location = f'{settings.GLOBAL_ISSUER_URL.rstrip("/")}/oauth/authorize?{urlencode(params)}'
        return HttpResponseRedirect(location)


class UpstreamCallbackView(FederationView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        if not is_region() or not _upstream_configured():
            return _disabled()
        state = (request.GET.get('state') or '').strip()
        saved = cache.get(f'federation:rp-state:{state}') if state else None
        if not isinstance(saved, dict):
            return Response({'error': 'invalid_state'}, status=400)
        cache.delete(f'federation:rp-state:{state}')
        company = Company.objects.filter(pk=saved['company_id']).first()
        redirect_to = saved.get('redirect_to') or ''
        if company is None:
            return Response({'error': 'invalid_state'}, status=400)
        upstream_error = (request.GET.get('error') or '').strip()
        if upstream_error:
            return _shell_error(request, redirect_to, upstream_error)
        code = (request.GET.get('code') or '').strip()
        if not code:
            return _shell_error(request, redirect_to, 'invalid_request')
        try:
            id_token = _exchange(code, saved)
            claims = verify_pinned(
                id_token,
                audience=settings.GLOBAL_CLIENT_ID,
                issuer_url=settings.GLOBAL_ISSUER_URL,
                require=['exp', 'iat', 'iss', 'aud', 'sub', 'nonce', 'email'],
            )
        except (TokenError, requests.RequestException, ValueError):
            logger.warning('upstream token rejected company_id=%s', company.pk)
            return _shell_error(request, redirect_to, 'invalid_token')
        if claims.get('nonce') != saved.get('nonce'):
            return _shell_error(request, redirect_to, 'invalid_token')
        if claims.get('email_verified') is not True:
            return _shell_error(request, redirect_to, 'email_not_verified')
        user, link_error = link_verified_user(claims)
        if link_error or user is None:
            return _shell_error(request, redirect_to, link_error or 'access_denied')
        join = apply_company_join(company, user, email=user.email)
        if not join.allowed:
            return _shell_error(request, redirect_to, join.error_code or 'access_denied')
        from apps.authapi.views import _finalize_shellui_oauth_login

        return _finalize_shellui_oauth_login(
            request,
            user=user,
            company=company,
            provider=PROVIDER,
            redirect_to=redirect_to,
            avatar_url=None,
            code_challenge=saved.get('shell_challenge') or None,
        )


def link_verified_user(claims: dict):
    """Create or link a local user. Never sets ``is_staff`` or ``is_superuser``."""
    if claims.get('email_verified') is not True:
        return None, 'email_not_verified'
    email = normalize_oauth_email(str(claims.get('email') or ''))
    issuer = str(claims.get('iss') or '').rstrip('/')
    sub = str(claims.get('sub') or '').strip()
    if not email or '@' not in email or not issuer or not sub:
        return None, 'invalid_token'
    name = claims.get('name') if isinstance(claims.get('name'), str) else ''
    try:
        with transaction.atomic():
            linked = (
                UpstreamAccount.objects.select_for_update()
                .filter(issuer=issuer, sub=sub)
                .select_related('user')
                .first()
            )
            if linked is not None:
                user = linked.user
                if not user.is_active:
                    return None, 'access_denied'
                if linked.email != email and not User.objects.filter(email__iexact=email).exclude(pk=user.pk).exists():
                    user.email = email
                    user.save(update_fields=['email'])
                    linked.email = email
                    linked.save(update_fields=['email'])
                return user, None
            user = User.objects.filter(email__iexact=email).order_by('pk').first()
            created = False
            if user is None:
                user = create_unprivileged_user(email=email, full_name=name)
                created = True
            elif not user.is_active:
                return None, 'access_denied'
            elif UpstreamAccount.objects.filter(user=user, issuer=issuer).exclude(sub=sub).exists():
                return None, 'subject_mismatch'
            UpstreamAccount.objects.create(user=user, issuer=issuer, sub=sub, email=email)
    except IntegrityError:
        logger.warning('upstream link conflict issuer=%s', issuer)
        return None, 'subject_mismatch'
    if created:
        user.refresh_from_db()
    return user, None


def _exchange(code: str, saved: dict) -> str:
    token_url = f'{settings.GLOBAL_ISSUER_URL.rstrip("/")}/oauth/token'
    response = requests.post(
        token_url,
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': saved['redirect_uri'],
            'client_id': settings.GLOBAL_CLIENT_ID,
            'client_secret': settings.GLOBAL_CLIENT_SECRET,
            'code_verifier': saved['verifier'],
        },
        timeout=10,
        allow_redirects=False,
    )
    if response.status_code != 200:
        raise TokenError('invalid_token')
    body = response.json()
    id_token = body.get('id_token') if isinstance(body, dict) else None
    if not isinstance(id_token, str) or not id_token:
        raise TokenError('invalid_token')
    return id_token


def _company_redirect(request):
    raw_company = (request.GET.get('company_id') or '').strip()
    try:
        company = Company.objects.get(pk=int(raw_company))
    except (Company.DoesNotExist, TypeError, ValueError):
        return None, None, Response({'error': 'Company not found.'}, status=404)
    redirect_to, err = validate_redirect_to_for_company(
        company=company,
        request=request,
        redirect_to_raw=request.GET.get('redirect_to'),
    )
    if err or not redirect_to:
        return None, None, Response({'error': err or 'Invalid redirect.'}, status=400)
    return company, redirect_to, None


def _redirect_uri(request) -> str:
    configured = (getattr(settings, 'GLOBAL_REDIRECT_URI', '') or '').strip()
    if configured:
        return configured
    base = (getattr(settings, 'JWT_ISSUER', None) or request.build_absolute_uri('/').rstrip('/')).rstrip('/')
    return f'{base}/oauth/upstream-callback'


def _upstream_configured() -> bool:
    return bool(
        (getattr(settings, 'GLOBAL_ISSUER_URL', '') or '').strip()
        and (getattr(settings, 'GLOBAL_CLIENT_ID', '') or '').strip()
        and (getattr(settings, 'GLOBAL_CLIENT_SECRET', '') or '').strip()
        and (getattr(settings, 'GLOBAL_JWKS', {}) or {}).get('keys')
    )


def _shell_error(request, redirect_to: str, code: str):
    location = append_oauth_error_params(redirect_to, 'Upstream sign-in was refused.', code)
    return client_redirect_response(
        request,
        location,
        succeeded=client_redirect_reports_success(location),
    )
