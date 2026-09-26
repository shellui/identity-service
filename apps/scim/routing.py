from __future__ import annotations

from apps.companies.models import Company


def scim_company_url_segment(company: Company) -> str:
    """Canonical SCIM URL path segment (numeric company primary key)."""
    return str(company.pk)


def scim_path_prefix_for_company(company: Company) -> str:
    return f'/api/v1/companies/{scim_company_url_segment(company)}/scim/v2/'


def scim_reverse_kwargs(company: Company, **extra) -> dict:
    """URL kwargs for reversing company-scoped ``scim:*`` routes (id-based path)."""
    return {'company_id': company.pk, **extra}


def resolve_company_from_scim_url_segment(segment: str) -> Company | None:
    """Resolve the company from the numeric id in the SCIM URL path."""
    if not segment.isdigit():
        return None
    return Company.objects.filter(pk=int(segment)).first()
