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


def is_company_controlled_idp(entry: ProviderCatalogEntry | None, *, social_app=None) -> bool:
    """Company-operated IdPs. Self-hosted GitLab counts; gitlab.com does not."""
    if entry is None:
        return False
    if entry.docs_slug in COMPANY_CONTROLLED_IDP_SLUGS:
        return True
    if entry.docs_slug == 'gitlab' and social_app is not None:
        from apps.authapi.oauth_provider_urls import is_self_hosted_gitlab

        return is_self_hosted_gitlab(social_app)
    return False


def requires_verified_id_token_for_login(entry: ProviderCatalogEntry | None) -> bool:
    if entry is None:
        return False
    if is_company_controlled_idp(entry):
        return True
    policy = entry.email_link_policy
    if policy in {'google_email_verified', 'oidc_email_verified_or_uid_only'}:
        return True
    if entry.docs_slug == 'linkedin':
        return True
    return False
