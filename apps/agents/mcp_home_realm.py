"""MCP sign-in home realm: route verified email domains to the company SSO/OAuth IdP."""

from __future__ import annotations

from django.http import HttpRequest, HttpResponseRedirect

from apps.agents.mcp_signin import signin_complete_url
from apps.authapi.oauth import social_app_catalog_slug
from apps.companies.access import normalize_allowed_domains
from apps.companies.domain_verification import shellui_verified_email_domains
from apps.companies.models import Company, CompanyOAuthClient


def email_domain(email: str) -> str:
    parts = str(email or '').strip().lower().rsplit('@', 1)
    return parts[1] if len(parts) == 2 else ''


def _active_sso_clients(company: Company) -> list[CompanyOAuthClient]:
    rows = list(
        CompanyOAuthClient.objects.filter(company=company, is_active=True)
        .exclude(social_app__client_id='')
        .select_related('social_app')
        .order_by('id')
    )
    out: list[CompanyOAuthClient] = []
    for row in rows:
        provider = str(row.social_app.provider or '').strip().lower()
        if provider == 'saml':
            out.append(row)
            continue
        if str(row.social_app.secret or '').strip():
            out.append(row)
    return out


def resolve_home_realm_client(company: Company, domain: str) -> CompanyOAuthClient | None:
    """Pick one IdP when the domain is Shellui-verified and matches IdP home-realm domains."""
    domain = str(domain or '').strip().lower()
    if not domain or domain not in shellui_verified_email_domains(company):
        return None
    candidates: list[CompanyOAuthClient] = []
    for row in _active_sso_clients(company):
        idp_domains = normalize_allowed_domains(getattr(row, 'sso_verified_domains', None) or [])
        if idp_domains:
            if domain in idp_domains:
                candidates.append(row)
        else:
            candidates.append(row)
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    strict = [
        row
        for row in candidates
        if domain in normalize_allowed_domains(getattr(row, 'sso_verified_domains', None) or [])
    ]
    if len(strict) == 1:
        return strict[0]
    return None


def home_realm_signin_redirect(
    request: HttpRequest,
    *,
    company: Company,
    email: str,
    redirect_to: str | None = None,
    code_challenge: str | None = None,
) -> HttpResponseRedirect | None:
    client_row = resolve_home_realm_client(company, email_domain(email))
    if client_row is None:
        return None
    from apps.authapi.views import _build_shellui_authorize_url

    provider = social_app_catalog_slug(client_row.social_app)
    location = _build_shellui_authorize_url(
        request,
        company=company,
        redirect_to=redirect_to or signin_complete_url(request),
        provider=provider,
        company_oauth_client_id=client_row.pk,
        code_challenge=code_challenge,
    )
    return HttpResponseRedirect(location)
