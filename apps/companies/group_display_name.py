"""Shared display_name uniqueness checks (manual + scim share one namespace per company)."""

from __future__ import annotations

from django.db.models import QuerySet

from apps.companies.models import Company, CompanyGroup


def display_name_conflicts(
    company: Company,
    display_name: str,
    *,
    exclude_pk: int | None = None,
) -> QuerySet[CompanyGroup]:
    name = (display_name or '').strip()
    if not name:
        return CompanyGroup.objects.none()
    qs = CompanyGroup.objects.filter(company=company, display_name=name)
    if exclude_pk is not None:
        qs = qs.exclude(pk=exclude_pk)
    return qs


def first_display_name_conflict(
    company: Company,
    display_name: str,
    *,
    exclude_pk: int | None = None,
) -> CompanyGroup | None:
    return display_name_conflicts(company, display_name, exclude_pk=exclude_pk).first()
