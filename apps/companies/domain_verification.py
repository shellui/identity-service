"""Shellui-verified company email domains (proof of ownership, not join allow-list)."""

from __future__ import annotations

from apps.companies.access import normalize_allowed_domains
from apps.companies.models import Company


def shellui_verified_email_domains(company: Company) -> frozenset[str]:
    raw = getattr(company, 'verified_email_domains', None)
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(normalize_allowed_domains(raw))
