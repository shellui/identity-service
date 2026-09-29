"""Guards for DELETE /api/v1/user (self-service account erasure)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from django.conf import settings
from rest_framework import status
from rest_framework.response import Response

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.http import HttpRequest


def _token_claims(request: HttpRequest) -> dict | None:
    auth = getattr(request, 'auth', None)
    if auth is None:
        return None
    if hasattr(auth, 'get'):
        return auth
    return None


def check_self_service_account_delete_allowed(
    request: HttpRequest,
    user: AbstractBaseUser,
) -> Response | None:
    """
    Return an error Response when deletion must be blocked; None when allowed.

    Requires a session access JWT (no ``pat_id``) whose ``iat`` is within
    ``settings.SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE``. Blocks global delete
    when the user still belongs to more than one company (company-scoped JWT).
    """
    claims = _token_claims(request)
    if claims is not None and claims.get('pat_id') is not None:
        return Response(
            {
                'error': (
                    'Personal access tokens cannot delete an account. '
                    'Sign in with OAuth or refresh your session access token, then try again.'
                ),
            },
            status=status.HTTP_403_FORBIDDEN,
        )

    max_age = getattr(settings, 'SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE', None)
    max_seconds = int(max_age.total_seconds()) if max_age is not None else 300
    if claims is not None:
        iat = claims.get('iat')
        if iat is None:
            return Response(
                {'error': 'Sign in again, then delete your account.'},
                status=status.HTTP_403_FORBIDDEN,
            )
        try:
            issued_at = int(iat)
        except (TypeError, ValueError):
            return Response(
                {'error': 'Sign in again, then delete your account.'},
                status=status.HTTP_403_FORBIDDEN,
            )
        age = int(time.time()) - issued_at
        if age > max_seconds:
            return Response(
                {
                    'error': (
                        'Account deletion requires a recently issued access token. '
                        'Sign in again, then try again.'
                    ),
                },
                status=status.HTTP_403_FORBIDDEN,
            )

    membership_count = user.company_memberships.count()
    if membership_count > 1:
        return Response(
            {
                'error': (
                    'This account belongs to more than one company. '
                    'Self-service deletion removes the global user for every company. '
                    'Leave or disable access in the other companies first (for example via your '
                    'administrator or SCIM deprovision), then delete when only one membership remains.'
                ),
            },
            status=status.HTTP_409_CONFLICT,
        )

    return None
