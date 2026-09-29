from __future__ import annotations

from apps.companies.models import Company


def get_scim_company(request) -> Company | None:
    return getattr(request, 'scim_company', None)
