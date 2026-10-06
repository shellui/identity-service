"""Company-scoped OpenID Connect discovery hosts for strict OAuth adapter tests."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OidcCompanyFixture:
    hostname: str
    issuer: str
    server_url: str


def company_linkedin_oidc(company_slug: str) -> OidcCompanyFixture:
    hostname = f'linkedin.{company_slug}.example.com'
    issuer = f'https://{hostname}/oauth'
    return OidcCompanyFixture(
        hostname=hostname,
        issuer=issuer,
        server_url=f'{issuer}/.well-known/openid-configuration',
    )


def company_keycloak_oidc(company_slug: str) -> OidcCompanyFixture:
    hostname = f'keycloak.{company_slug}.example.com'
    issuer = f'https://{hostname}/realms/fixture'
    return OidcCompanyFixture(
        hostname=hostname,
        issuer=issuer,
        server_url=f'{issuer}/.well-known/openid-configuration',
    )


def company_generic_oidc(company_slug: str) -> OidcCompanyFixture:
    hostname = f'oidc.{company_slug}.example.com'
    issuer = f'https://{hostname}'
    return OidcCompanyFixture(
        hostname=hostname,
        issuer=issuer,
        server_url=f'{issuer}/.well-known/openid-configuration',
    )


def company_okta_base(company_slug: str) -> str:
    return f'https://dev-{company_slug}.okta.example.com'


def company_auth0_base(company_slug: str) -> str:
    return f'https://tenant-{company_slug}.auth0.example.com'
