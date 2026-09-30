"""Email-link and identity policies for OAuth / OIDC providers."""

from __future__ import annotations

from apps.authapi.provider_registry import ProviderCatalogEntry

# Company owners control these IdPs; never auto-link by email until domain verification exists.
COMPANY_CONTROLLED_IDP_SLUGS = frozenset(
    {
        'openid_connect',
        'keycloak',
        'okta',
        'auth0',
    }
)

COMPANY_IDP_EMAIL_LINK_POLICY = 'company_idp_uid_only'


def is_company_controlled_idp(entry: ProviderCatalogEntry | None) -> bool:
    if entry is None:
        return False
    return entry.docs_slug in COMPANY_CONTROLLED_IDP_SLUGS


def requires_verified_id_token_for_login(entry: ProviderCatalogEntry | None) -> bool:
    if entry is None:
        return False
    policy = entry.email_link_policy
    if policy in {'google_email_verified', 'oidc_email_verified_or_uid_only'}:
        return True
    if entry.docs_slug == 'linkedin':
        return True
    return False
