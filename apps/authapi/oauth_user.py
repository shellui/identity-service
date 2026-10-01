"""OAuth profile extraction and safe user resolution (verified email linking)."""

from __future__ import annotations

import json
import logging
import unicodedata
import urllib.request
from dataclasses import dataclass

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction

from apps.authapi.oauth_idp_policy import (
    COMPANY_IDP_EMAIL_LINK_POLICY,
    is_company_controlled_idp,
)
from apps.authapi.provider_registry import ProviderCatalogEntry, resolve_catalog_slug
from apps.authapi.oauth_social_account import compose_social_account_uid, social_account_provider_key

User = get_user_model()
logger = logging.getLogger(__name__)


def normalize_oauth_email(email: str) -> str:
    return unicodedata.normalize('NFKC', (email or '').strip()).casefold()


def get_or_create_user_for_oauth(*, email: str, defaults: dict) -> tuple[User, bool]:
    """
    Resolve a user by email without raising MultipleObjectsReturned.

    Matches are case-insensitive. When several rows share the same email, the lowest pk wins
    and a warning is logged so operators can run duplicate-email cleanup.
    """
    normalized = normalize_oauth_email(email)
    if not normalized:
        raise ValueError('OAuth email is required.')

    matches = list(User.objects.filter(email__iexact=normalized).order_by('pk')[:2])
    if len(matches) >= 2:
        logger.warning(
            'Multiple users share email %r (pks include %s and %s); OAuth will use pk=%s',
            normalized,
            matches[0].pk,
            matches[1].pk,
            matches[0].pk,
        )
    if matches:
        return matches[0], False

    create_defaults = {**defaults, 'email': normalized}
    user = User.objects.create(**create_defaults)
    user.set_unusable_password()
    user.save(update_fields=['password'])
    return user, True


def _backfill_user_names_from_profile(user: User, profile: OAuthProfile) -> None:
    """Fill the name only when the user has none, so a user-chosen name is never overwritten."""
    if user.first_name or user.last_name or not profile.full_name:
        return
    user.first_name = profile.full_name.split(' ')[0]
    user.last_name = ' '.join(profile.full_name.split(' ')[1:])
    user.save(update_fields=['first_name', 'last_name'])


@dataclass(frozen=True)
class OAuthProfile:
    provider_id: str
    social_provider: str
    social_uid: str
    email: str
    full_name: str
    avatar_url: str | None
    email_verified_for_link: bool
    userinfo: dict
    company_controlled_idp: bool = False


_SUBJECT_BOUND_ALLAUTH_IDS = frozenset({'openid_connect', 'okta', 'auth0', 'google'})


def _provider_uid_from_userinfo(
    *,
    info: dict,
    entry: ProviderCatalogEntry | None,
    social_app,
    id_token_claims: dict | None = None,
) -> str:
    info_sub = info.get('sub')
    info_sub = info_sub.strip() if isinstance(info_sub, str) else ''
    claim_sub = ''
    if isinstance(id_token_claims, dict) and isinstance(id_token_claims.get('sub'), str):
        claim_sub = id_token_claims['sub'].strip()
    if entry is not None and entry.allauth_id in _SUBJECT_BOUND_ALLAUTH_IDS and claim_sub and not info_sub:
        return ''
    stored = info.get('_allauth_account_uid')
    if isinstance(stored, str) and stored.strip():
        return stored.strip()
    if entry is not None and social_app is not None:
        from django.test import RequestFactory

        from allauth.socialaccount.providers import registry

        request = RequestFactory().get('/')
        try:
            provider = registry.get_class(entry.allauth_id)(request, app=social_app)
            return str(provider.extract_uid(info)).strip()
        except (KeyError, TypeError, ValueError):
            pass
    return str(
        info.get('id')
        or info.get('sub')
        or info.get('userPrincipalName')
        or info.get('mail')
        or ''
    ).strip()


def _truthy_claim(value: object) -> bool:
    return value is True or value == 'true' or value == 1 or value == '1'


def microsoft_email_trustworthy(
    *,
    tenant: str | None,
    id_token_claims: dict,
    configured_tenant: str | None = None,
) -> bool:
    import re

    guid_re = re.compile(r'^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$', re.IGNORECASE)
    configured = (configured_tenant or tenant or 'common').strip()
    tid = str(id_token_claims.get('tid') or '').strip()
    if configured and guid_re.match(configured):
        return bool(tid) and tid.lower() == configured.lower()
    if configured and configured.lower() not in ('common', 'organizations', 'consumers'):
        from apps.authapi.oauth_id_token import microsoft_tenant_guid_for_domain

        expected = microsoft_tenant_guid_for_domain(configured)
        if not expected:
            return False
        return bool(tid) and tid.lower() == expected.lower()
    return _truthy_claim(id_token_claims.get('xms_edov'))


def _fetch_github_verified_primary_email(access_token: str) -> tuple[str | None, bool]:
    req = urllib.request.Request(
        'https://api.github.com/user/emails',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        emails = json.loads(response.read().decode('utf-8'))
    if not isinstance(emails, list):
        return None, False
    primary = next((item for item in emails if isinstance(item, dict) and item.get('primary')), None)
    if not primary or not _truthy_claim(primary.get('verified')):
        return None, False
    email = primary.get('email')
    if isinstance(email, str) and email.strip():
        return email.strip().lower(), True
    return None, False


def _email_verified_for_link_from_policy(
    *,
    policy: str,
    provider_key: str,
    userinfo: dict,
    access_token: str,
    tenant: str | None,
    id_token_claims: dict,
) -> tuple[bool, str | None, str | None]:
    """Return (verified_for_link, error_message, resolved_email_override)."""
    info = userinfo if isinstance(userinfo, dict) else {}
    claims = id_token_claims if isinstance(id_token_claims, dict) else {}

    if policy == 'github_verified_primary':
        gh_email, verified = _fetch_github_verified_primary_email(access_token)
        if verified and gh_email:
            return True, None, gh_email
        return False, (
            'GitHub sign-in requires a verified primary email on your account. '
            'Verify your email at GitHub, then try again.'
        ), None

    if policy == 'google_email_verified':
        claim_email = claims.get('email')
        if (
            claims
            and _truthy_claim(claims.get('email_verified'))
            and isinstance(claim_email, str)
            and claim_email.strip()
        ):
            if isinstance(info.get('email'), str) and claim_email.strip().lower() == str(info.get('email')).strip().lower():
                return True, None, None
            return False, None, None
        return False, None, None

    if policy == COMPANY_IDP_EMAIL_LINK_POLICY:
        return False, None, None

    if policy == 'discord_email_verified':
        return _truthy_claim(info.get('verified')), None, None

    if policy == 'kakao_email_verified':
        return _truthy_claim(info.get('is_email_verified')), None, None

    if policy == 'microsoft_tenant':
        if not claims or not str(claims.get('tid') or '').strip():
            return False, (
                'Microsoft sign-in requires a verified ID token from your tenant.'
            ), None
        if not microsoft_email_trustworthy(
            tenant=tenant,
            id_token_claims=claims,
            configured_tenant=tenant,
        ):
            return False, (
                'Microsoft sign-in requires a verified work account or a company-configured tenant. '
                'Ask your administrator to restrict sign-in to your organization tenant.'
            ), None
        ms_email = info.get('mail') or info.get('userPrincipalName') or info.get('email')
        if isinstance(ms_email, str) and ms_email.strip() and '@' in ms_email:
            return True, None, ms_email.strip().lower()
        return False, None, None

    if policy == COMPANY_IDP_EMAIL_LINK_POLICY:
        return False, None, None

    if policy == 'oidc_email_verified_or_uid_only':
        if not claims or not str(claims.get('iss') or '').strip():
            return False, None, None
        claim_email = claims.get('email')
        if (
            _truthy_claim(claims.get('email_verified'))
            and isinstance(claim_email, str)
            and claim_email.strip()
            and isinstance(info.get('email'), str)
            and claim_email.strip().lower() == str(info.get('email')).strip().lower()
        ):
            return True, None, None
        return False, None, None

    if policy == 'oauth2_email_verified_or_uid_only':
        if _truthy_claim(info.get('email_verified')):
            return True, None, None
        return False, None, None

    if policy == 'uid_only':
        return False, None, None

    return False, None, None


def extract_oauth_profile(
    provider: str,
    userinfo: dict,
    access_token: str,
    *,
    tenant: str | None = None,
    id_token_claims: dict | None = None,
    catalog_entry: ProviderCatalogEntry | None = None,
    social_app=None,
) -> tuple[OAuthProfile | None, str | None]:
    key = str(provider).strip().lower()
    entry = catalog_entry or resolve_catalog_slug(key)
    policy = entry.email_link_policy if entry is not None else 'uid_only'
    company_controlled = is_company_controlled_idp(entry, social_app=social_app)
    if company_controlled:
        policy = COMPANY_IDP_EMAIL_LINK_POLICY
    info = userinfo if isinstance(userinfo, dict) else {}
    claims = id_token_claims if isinstance(id_token_claims, dict) else {}
    if social_app is not None and entry is not None:
        social_provider = social_account_provider_key(entry=entry, social_app=social_app)
    else:
        social_provider = entry.allauth_id if entry is not None else key

    provider_id = _provider_uid_from_userinfo(
        info=info,
        entry=entry,
        social_app=social_app,
        id_token_claims=claims,
    )
    if not provider_id:
        return None, 'OAuth provider did not return a user id.'

    email = info.get('email') or info.get('mail') or info.get('userPrincipalName')
    full_name = info.get('name') or info.get('displayName') or ''
    email_verified_for_link, policy_error, email_override = _email_verified_for_link_from_policy(
        policy=policy,
        provider_key=social_provider,
        userinfo=info,
        access_token=access_token,
        tenant=tenant,
        id_token_claims=claims,
    )
    if policy_error:
        return None, policy_error
    if email_override:
        email = email_override

    if not email or not str(email).strip():
        email = f'{provider_id}@{social_provider}.local'
    else:
        email = str(email).strip().lower()

    if not full_name:
        full_name = email.split('@')[0]

    avatar_url = info.get('avatar_url') or info.get('picture') or info.get('photo')
    if not isinstance(avatar_url, str) or not avatar_url.strip():
        avatar_url = None

    social_uid = compose_social_account_uid(
        entry=entry,
        social_app=social_app,
        raw_uid=provider_id,
        id_token_claims=claims,
    ) if social_app is not None else provider_id

    return OAuthProfile(
        provider_id=provider_id,
        social_provider=social_provider,
        social_uid=social_uid or provider_id,
        email=email,
        full_name=str(full_name),
        avatar_url=avatar_url,
        email_verified_for_link=email_verified_for_link,
        userinfo=info,
        company_controlled_idp=company_controlled,
    ), None


def _company_idp_claimed_email_conflict(
    *,
    profile: OAuthProfile,
    social_key: str,
    social_uid: str,
    catalog_entry: ProviderCatalogEntry | None,
) -> str | None:
    if not (profile.company_controlled_idp or is_company_controlled_idp(catalog_entry)):
        return None
    claimed = normalize_oauth_email(profile.email)
    if not claimed or '@' not in claimed:
        return None
    if claimed.endswith(f'@{social_key}.local'):
        return None
    existing_user = User.objects.filter(email__iexact=claimed).first()
    if existing_user is None:
        return None
    already_linked = SocialAccount.objects.filter(
        provider=social_key,
        uid=social_uid,
        user=existing_user,
    ).exists()
    if already_linked:
        return None
    return 'oauth_email_conflict'


def resolve_oauth_user(
    *,
    provider: str,
    profile: OAuthProfile,
    catalog_entry: ProviderCatalogEntry | None = None,
) -> tuple[User | None, bool, str | None, str | None]:
    """
    Link by (provider, uid) first. Link by email only when ``email_verified_for_link`` is true.
    Returns (user, created, error_message, error_code).
    """
    key = str(provider).strip().lower()
    entry = catalog_entry or resolve_catalog_slug(key)
    social_key = profile.social_provider
    social_uid = profile.social_uid
    existing = (
        SocialAccount.objects.filter(provider=social_key, uid=social_uid)
        .select_related('user')
        .first()
    )
    if existing is not None:
        return existing.user, False, None, None

    uid_local_part = f'{social_key}_{social_uid}'
    if len(uid_local_part) > 150:
        uid_local_part = f'{social_key}_{hash(social_uid) & 0xFFFFFFFFFFFF:x}'

    with transaction.atomic():
        existing = (
            SocialAccount.objects.select_for_update()
            .filter(provider=social_key, uid=social_uid)
            .select_related('user')
            .first()
        )
        if existing is not None:
            return existing.user, False, None, None

        conflict = _company_idp_claimed_email_conflict(
            profile=profile,
            social_key=social_key,
            social_uid=social_uid,
            catalog_entry=entry,
        )
        if conflict:
            return None, False, 'OAuth email is already used by another account.', conflict

        if not profile.email_verified_for_link:
            uid_email = f'{social_uid}@{social_key}.local'
            user, created = User.objects.get_or_create(
                email=uid_email,
                defaults={
                    'username': uid_local_part[:150],
                    'first_name': profile.full_name.split(' ')[0],
                    'last_name': ' '.join(profile.full_name.split(' ')[1:]),
                },
            )
            if created:
                user.set_unusable_password()
                user.save(update_fields=['password'])
            try:
                SocialAccount.objects.create(
                    provider=social_key,
                    uid=social_uid,
                    user=user,
                    extra_data=profile.userinfo,
                )
            except IntegrityError:
                linked = (
                    SocialAccount.objects.filter(provider=social_key, uid=social_uid)
                    .select_related('user')
                    .first()
                )
                if linked is None:
                    raise
                return linked.user, False, None, None
            return user, created, None, None

        user, created = get_or_create_user_for_oauth(
            email=profile.email,
            defaults={
                'username': uid_local_part[:150],
                'first_name': profile.full_name.split(' ')[0],
                'last_name': ' '.join(profile.full_name.split(' ')[1:]),
            },
        )
        if not created:
            _backfill_user_names_from_profile(user, profile)
        try:
            SocialAccount.objects.create(
                provider=social_key,
                uid=social_uid,
                user=user,
                extra_data=profile.userinfo,
            )
        except IntegrityError:
            linked = (
                SocialAccount.objects.filter(provider=social_key, uid=social_uid)
                .select_related('user')
                .first()
            )
            if linked is None:
                raise
            return linked.user, False, None, None

    return user, created, None, None
