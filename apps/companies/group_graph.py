"""Nested company group graph: cycle checks and effective user membership."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db.models import QuerySet

from .models import Company, CompanyGroup

User = get_user_model()


class NestedGroupCycleError(ValueError):
    """Raised when a nested group link would create a cycle or self-membership."""


def would_create_group_cycle(parent: CompanyGroup, child: CompanyGroup) -> bool:
    """
    Return True if adding ``child`` as a member group of ``parent`` would create a cycle.

    Walk nested members starting from ``child``; if ``parent`` is reachable, the new edge closes a loop.
    """
    if parent.pk is not None and child.pk is not None and parent.pk == child.pk:
        return True
    if parent.pk is None or child.pk is None:
        return parent is child

    stack = list(child.member_groups.all())
    seen: set[int] = set()
    while stack:
        nested = stack.pop()
        if nested.pk in seen:
            continue
        seen.add(nested.pk)
        if nested.pk == parent.pk:
            return True
        stack.extend(nested.member_groups.all())
    return False


def assert_nested_group_link_allowed(parent: CompanyGroup, child: CompanyGroup) -> None:
    if parent.company_id != child.company_id:
        raise NestedGroupCycleError('Nested group members must belong to the same company.')
    if would_create_group_cycle(parent, child):
        raise NestedGroupCycleError('Nested group membership would create a cycle or self-reference.')


def effective_user_ids_for_group(group: CompanyGroup) -> set[int]:
    """
    All user ids in ``group`` including users in nested member groups (transitive, cycle-safe).
    """
    user_ids: set[int] = set(group.members.values_list('pk', flat=True))
    seen_groups: set[int] = set()
    stack = list(group.member_groups.all())
    while stack:
        nested = stack.pop()
        if nested.pk in seen_groups:
            continue
        seen_groups.add(nested.pk)
        user_ids.update(nested.members.values_list('pk', flat=True))
        stack.extend(nested.member_groups.all())
    return user_ids


def effective_users_for_group(group: CompanyGroup) -> QuerySet:
    """QuerySet of users with effective membership in ``group`` (nested groups included)."""
    ids = effective_user_ids_for_group(group)
    if not ids:
        return User.objects.none()
    return User.objects.filter(pk__in=ids)


def effective_users_for_company_groups(company: Company, groups: QuerySet[CompanyGroup]) -> QuerySet:
    """Union of effective users across multiple groups in a company."""
    all_ids: set[int] = set()
    for group in groups.filter(company=company):
        all_ids.update(effective_user_ids_for_group(group))
    if not all_ids:
        return User.objects.none()
    return User.objects.filter(pk__in=all_ids)
