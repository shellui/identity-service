"""Guards for DELETE /api/v1/user (self-service account erasure)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from django.conf import settings
from django.db.models import Count
from rest_framework import status
from rest_framework.response import Response

from apps.companies.models import Company

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.http import HttpRequest

RECENT_LOGIN_REQUIRED = 'recent_login_required'
LAST_COMPANY_OWNER = 'last_company_owner'


def _token_claims(request: HttpRequest) -> dict | None:
    auth = getattr(request, 'auth', None)
    if auth is None:
        return None
    if hasattr(auth, 'get'):
        return auth
    return None


def sole_owner_companies(user: AbstractBaseUser, company: Company) -> list[Company]:
    """
    Companies that would be left without an owner if ``user`` deleted their account from ``company``.

    When the user keeps other memberships only ``company`` is affected; otherwise the whole
    account goes, which also drops ownership of any other company.
    """
    owned_ids = Company.objects.filter(owners=user).values_list('pk', flat=True)
    if user.company_memberships.exclude(company=company).exists():
        owned_ids = owned_ids.filter(pk=company.pk)
    return list(
        Company.objects.filter(pk__in=owned_ids)
        .annotate(owner_count=Count('owners', distinct=True))
        .filter(owner_count=1)
        .order_by('name')
    )


def check_self_service_account_delete_allowed(
    request: HttpRequest,
    user: AbstractBaseUser,
    company: Company,
) -> Response | None:
    """
    Return an error Response when deletion must be blocked; None when allowed.

    Requires a session access JWT (no ``pat_id``) whose ``auth_time`` is within
    ``settings.SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE``, and refuses when the user is the
    only owner of a company that would lose them (409 ``last_company_owner``).
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

    orphaned = sole_owner_companies(user, company)
    if orphaned:
        names = ', '.join(c.name for c in orphaned)
        return Response(
            {
                'error': (
                    f'You are the only owner of {names}. '
                    'Add another owner before deleting your account.'
                ),
                'error_code': LAST_COMPANY_OWNER,
                'companies': [{'id': c.pk, 'name': c.name} for c in orphaned],
            },
            status=status.HTTP_409_CONFLICT,
        )

    max_age = getattr(settings, 'SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE', None)
    max_seconds = int(max_age.total_seconds()) if max_age is not None else 300
    if claims is not None:
        auth_time = claims.get('auth_time')
        if auth_time is None:
            return _recent_login_required('Sign in again, then delete your account.')
        try:
            authenticated_at = int(auth_time)
        except (TypeError, ValueError):
            return _recent_login_required('Sign in again, then delete your account.')
        age = int(time.time()) - authenticated_at
        if age > max_seconds:
            return _recent_login_required(
                'Account deletion requires a recent sign-in. Sign in again, then try again.'
            )

    return None


def _recent_login_required(message: str) -> Response:
    return Response(
        {'error': message, 'error_code': RECENT_LOGIN_REQUIRED},
        status=status.HTTP_403_FORBIDDEN,
    )
