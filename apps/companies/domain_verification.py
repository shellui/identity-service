"""
Shellui-verified company email domains for SAML email linking.

These domains are not the same as ``allowed_email_domains`` (join allow-list).

Only Shellui platform operators may set ``Company.verified_email_domains`` (Django admin
or direct database maintenance). The company owner API never reads or writes this field.
Future DNS TXT verification would populate it via dedicated endpoints, not company settings.
"""

from __future__ import annotations

from apps.companies.access import normalize_allowed_domains
from apps.companies.models import Company


def shellui_verified_email_domains(company: Company) -> frozenset[str]:
    raw = getattr(company, 'verified_email_domains', None)
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(normalize_allowed_domains(raw))
