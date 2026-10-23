"""OAuth 2.0 Token Exchange (RFC 8693) on a regional server.

A shell signed in to the global identity server sends its global access token
here and gets a session for one regional company. The global token is checked
offline against the pinned GLOBAL_JWKS. The user is linked exactly like the
upstream silent sign-in does, and the company join rules are the same.
Tokens are never logged.
"""

from __future__ import annotations

import logging

from django.conf import settings
from rest_framework.response import Response

from apps.authapi.login_audit import LoginOutcome, record_login_event
from apps.authapi.throttling import check_rate_limit
from apps.companies.access import apply_company_join
from apps.companies.models import Company
from apps.federation.role import is_region
from apps.federation.signing import TokenError, verify_pinned

logger = logging.getLogger(__name__)

GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange'
ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
PROVIDER = 'upstream'


def exchange_enabled() -> bool:
    return bool(
        is_region()
        and (getattr(settings, 'GLOBAL_ISSUER_URL', '') or '').strip()
        and (getattr(settings, 'GLOBAL_ACCESS_TOKEN_AUDIENCE', '') or '').strip()
        and (getattr(settings, 'GLOBAL_JWKS', {}) or {}).get('keys')
    )


def _error(code: str, description: str, status: int = 400) -> Response:
    return Response({'error': code, 'error_description': description}, status=status)


def handle_token_exchange(request) -> Response:
    if not exchange_enabled():
        return Response(status=404)
    origin = request.headers.get('Origin', '')
    if origin and origin not in set(getattr(settings, 'OIDC_CORS_ALLOWED_ORIGINS', []) or []):
        return _error('invalid_request', 'Origin is not allowed.', status=403)
    limited = check_rate_limit(request, scope='token_exchange')
    if limited is not None:
        return limited

    data = request.data
    if str(data.get('subject_token_type') or '') != ACCESS_TOKEN_TYPE:
        return _error('invalid_request', 'subject_token_type must be an access token.')
    requested = str(data.get('requested_token_type') or ACCESS_TOKEN_TYPE)
    if requested != ACCESS_TOKEN_TYPE:
        return _error('invalid_request', 'Only access tokens can be requested.')
    subject_token = str(data.get('subject_token') or '').strip()
    if not subject_token:
        return _error('invalid_request', 'Missing subject_token.')
    try:
        company = Company.objects.get(pk=int(str(data.get('company_id') or '').strip()))
    except (Company.DoesNotExist, TypeError, ValueError):
        return _error('invalid_target', 'Company not found.')

    try:
        claims = verify_pinned(
            subject_token,
            audience=settings.GLOBAL_ACCESS_TOKEN_AUDIENCE,
            issuer_url=settings.GLOBAL_ISSUER_URL,
            require=['exp', 'iat', 'iss', 'aud', 'sub', 'email', 'jti'],
        )
    except TokenError:
        logger.info('token exchange: subject token rejected company_id=%s', company.pk)
        return _error('invalid_grant', 'The global access token is not valid.')
    # Only a short-lived, session-bound sign-in token. No refresh tokens, no personal access tokens.
    if claims.get('token_type') != 'access' or not claims.get('sid') or 'pat_id' in claims:
        return _error('invalid_grant', 'The subject token must be a global session access token.')
    if claims.get('email_verified') is not True:
        return _error('invalid_grant', 'The email address is not verified on the global server.')

    metadata = claims.get('user_metadata') if isinstance(claims.get('user_metadata'), dict) else {}
    link_claims = {
        'iss': claims.get('iss'),
        'sub': claims.get('sub'),
        'email': claims.get('email'),
        'email_verified': True,
        'name': metadata.get('full_name') or metadata.get('name') or '',
    }
    from apps.federation.relying import link_verified_user

    user, link_error = link_verified_user(link_claims)
    if link_error or user is None:
        return _error('invalid_grant', link_error or 'access_denied')
    join = apply_company_join(company, user, email=user.email)
    if not join.allowed:
        return _error('invalid_grant', join.error_code or 'access_denied')

    from apps.authapi.views import _issue_shellui_tokens

    payload = _issue_shellui_tokens(user, company=company, avatar_url=None, oauth_provider=PROVIDER)
    record_login_event(
        request=request,
        outcome=LoginOutcome.SUCCESS,
        provider=PROVIDER,
        user=user,
        company=company,
    )
    logger.info('token exchange: issued company_id=%s user_id=%s', company.pk, user.pk)
    return Response(
        {
            'access_token': payload['access_token'],
            'issued_token_type': ACCESS_TOKEN_TYPE,
            'token_type': 'Bearer',
            'expires_in': payload['expires_in'],
            'expires_at': payload['expires_at'],
            'refresh_token': payload['refresh_token'],
        },
        headers={'Cache-Control': 'no-store', 'Pragma': 'no-cache'},
    )
