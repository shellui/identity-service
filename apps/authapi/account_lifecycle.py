"""Hard-delete user accounts (admin or self-service) with action events and session cleanup."""

from __future__ import annotations

from allauth.socialaccount.models import SocialAccount, SocialApp
from django.core.cache import cache
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.actions.user_hooks import emit_user_account_deleted, emit_user_deleted_for_all_companies
from apps.companies.models import Company, CompanyGroup, CompanyMembership

from .models import (
    LoginEvent,
    MagicLinkToken,
    OAuthSessionDeliveryCode,
    PersonalAccessToken,
    RefreshTokenSession,
)
from .refresh_sessions import revoke_all_refresh_sessions_for_user


def invalidate_user_auth_state(user) -> None:
    """Revoke refresh sessions and PAT rows so outstanding tokens stop working promptly."""
    revoke_all_refresh_sessions_for_user(user)
    PersonalAccessToken.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=timezone.now())
    cache.delete(f'shellui:user_metadata:{user.id}')


def invalidate_user_company_auth_state(user, company) -> None:
    """Revoke refresh sessions and PATs scoped to one company (SCIM deprovisioning)."""
    now = timezone.now()
    RefreshTokenSession.objects.filter(
        user=user,
        company=company,
        revoked_at__isnull=True,
    ).update(revoked_at=now)
    PersonalAccessToken.objects.filter(
        user=user,
        company=company,
        revoked_at__isnull=True,
    ).update(revoked_at=now)


def delete_user_account(user, *, source: str) -> None:
    """
    Emit ``identity.user.deleted`` once per company membership, then remove the user row.

    Matches Django admin delete semantics (hard delete with cascading FKs).
    """
    invalidate_user_auth_state(user)
    emit_user_deleted_for_all_companies(user, source=source)
    user.delete()


def _company_only_social_provider_ids(company) -> list[str]:
    """Provider ids of SocialApps owned by ``company`` and not shared with any other company."""
    own = set(
        SocialApp.objects.filter(company_oauth_clients__company=company)
        .exclude(provider_id='')
        .values_list('provider_id', flat=True)
    )
    if not own:
        return []
    shared = set(
        SocialApp.objects.filter(provider_id__in=own)
        .exclude(company_oauth_clients__company=company)
        .values_list('provider_id', flat=True)
    )
    return sorted(own - shared)


@transaction.atomic
def remove_user_from_company(user, company, *, source: str) -> None:
    """
    Erase the user's data scoped to ``company`` and keep the account for their other companies.

    Emits ``identity.user.deleted`` for ``company`` only. Login audit rows for the company are
    kept but detached from the user, matching what a full account delete does.
    """
    emit_user_account_deleted(company, user, source=source)
    RefreshTokenSession.objects.filter(user=user, company=company).delete()
    PersonalAccessToken.objects.filter(user=user, company=company).delete()
    OAuthSessionDeliveryCode.objects.filter(user=user, company=company).delete()
    magic_link_owner = Q(user=user)
    if user.email:
        magic_link_owner |= Q(email__iexact=user.email)
    MagicLinkToken.objects.filter(magic_link_owner, company=company).delete()
    provider_ids = _company_only_social_provider_ids(company)
    if provider_ids:
        SocialAccount.objects.filter(user=user, provider__in=provider_ids).delete()
    user.company_groups.remove(*CompanyGroup.objects.filter(company=company, members=user))
    company.owners.remove(user)
    LoginEvent.objects.filter(user=user, company=company).update(user=None)
    CompanyMembership.objects.filter(user=user, company=company).delete()
    cache.delete(f'shellui:user_metadata:{user.id}')


def has_other_company_links(user, company) -> bool:
    """
    True when ``user`` is tied to any company besides ``company``.

    Ownership and groups count as well as memberships: Django admin can set owners or group
    members without a membership row, and deleting the account would strip them from that company.
    """
    return (
        CompanyMembership.objects.filter(user=user).exclude(company=company).exists()
        or Company.objects.filter(owners=user).exclude(pk=company.pk).exists()
        or CompanyGroup.objects.filter(members=user).exclude(company=company).exists()
    )


@transaction.atomic
def delete_user_for_company(user, company, *, source: str) -> bool:
    """
    Remove ``user`` from ``company``. The account row is deleted only when no other company
    links remain. Returns True when the whole account was deleted.
    """
    if has_other_company_links(user, company):
        remove_user_from_company(user, company, source=source)
        return False
    delete_user_account(user, source=source)
    return True
