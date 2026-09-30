"""SAML user resolution: never trust IdP email attributes for linking unless Shellui verified the domain."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp, SocialAccount

from apps.authapi.oauth_user import OAuthProfile, normalize_oauth_email, resolve_oauth_user
from apps.companies.domain_verification import shellui_verified_email_domains
from apps.companies.models import Company
from django.contrib.auth import get_user_model

User = get_user_model()

SAML_EMAIL_CONFLICT = 'saml_email_conflict'


def _assertion_email_from_profile(profile: OAuthProfile) -> str | None:
    raw = str(profile.email or '').strip()
    if not raw or raw.endswith('@saml.local'):
        return None
    normalized = normalize_oauth_email(raw)
    return normalized or None


def saml_may_link_existing_user_by_email(
    *,
    company: Company,
    social_app: SocialApp,
    assertion_email: str,
) -> bool:
    settings_data = social_app.settings if isinstance(getattr(social_app, 'settings', None), dict) else {}
    if not settings_data.get('trusted_for_verified_domains'):
        return False
    domain = assertion_email.rsplit('@', 1)[-1].strip().lower()
    if not domain:
        return False
    return domain in shellui_verified_email_domains(company)


def _profile_for_email_link(profile: OAuthProfile, *, assertion_email: str) -> OAuthProfile:
    return OAuthProfile(
        provider_id=profile.provider_id,
        social_provider=profile.social_provider,
        social_uid=profile.social_uid,
        email=assertion_email,
        full_name=profile.full_name,
        avatar_url=profile.avatar_url,
        email_verified_for_link=True,
        userinfo=profile.userinfo,
    )


def resolve_saml_user(
    *,
    company: Company,
    social_app: SocialApp,
    profile: OAuthProfile,
) -> tuple[User | None, bool, str | None]:
    """
    Resolve or create a user for a validated SAML assertion.

    IdP ``email_verified`` (or similar) attributes are ignored. Linking by assertion email
    happens only when the IdP is trusted and the email domain is Shellui-verified for the company.
    """
    social_key = profile.social_provider
    social_uid = profile.social_uid
    existing_sa = (
        SocialAccount.objects.filter(provider=social_key, uid=social_uid)
        .select_related('user')
        .first()
    )
    if existing_sa is not None:
        return existing_sa.user, False, None

    assertion_email = _assertion_email_from_profile(profile)
    if assertion_email:
        existing_users = list(User.objects.filter(email__iexact=assertion_email).order_by('pk')[:2])
        if existing_users:
            owner = existing_users[0]
            other_sa = SocialAccount.objects.filter(provider=social_key, user=owner).first()
            if other_sa is not None and str(other_sa.uid) != str(social_uid):
                return None, False, SAML_EMAIL_CONFLICT
            if not saml_may_link_existing_user_by_email(
                company=company,
                social_app=social_app,
                assertion_email=assertion_email,
            ):
                return None, False, SAML_EMAIL_CONFLICT
            link_profile = _profile_for_email_link(profile, assertion_email=assertion_email)
            return resolve_oauth_user(provider='saml', profile=link_profile)

        if saml_may_link_existing_user_by_email(
            company=company,
            social_app=social_app,
            assertion_email=assertion_email,
        ):
            link_profile = _profile_for_email_link(profile, assertion_email=assertion_email)
            return resolve_oauth_user(provider='saml', profile=link_profile)

    uid_only = OAuthProfile(
        provider_id=profile.provider_id,
        social_provider=profile.social_provider,
        social_uid=profile.social_uid,
        email=profile.email,
        full_name=profile.full_name,
        avatar_url=profile.avatar_url,
        email_verified_for_link=False,
        userinfo=profile.userinfo,
    )
    return resolve_oauth_user(provider='saml', profile=uid_only)
