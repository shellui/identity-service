"""OAuth profile extraction and safe user resolution (verified email linking)."""

from __future__ import annotations

import json
import logging
import unicodedata
import urllib.request
from dataclasses import dataclass

import jwt
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model

from apps.authapi.provider_registry import resolve_catalog_slug

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
    updates: list[str] = []
    if not user.first_name and profile.full_name:
        user.first_name = profile.full_name.split(' ')[0]
        updates.append('first_name')
    if not user.last_name and ' ' in profile.full_name:
        user.last_name = ' '.join(profile.full_name.split(' ')[1:])
        updates.append('last_name')
    if updates:
        user.save(update_fields=updates)


@dataclass(frozen=True)
class OAuthProfile:
    provider_id: str
    email: str
    full_name: str
    avatar_url: str | None
    email_verified_for_link: bool
    userinfo: dict


def decode_oauth_id_token_claims(id_token: str | None) -> dict:
    raw = (id_token or '').strip()
    if not raw:
        return {}
    try:
        claims = jwt.decode(
            raw,
            options={'verify_signature': False},
            algorithms=['RS256', 'HS256', 'RS384', 'RS512'],
        )
    except Exception:
        return {}
    return claims if isinstance(claims, dict) else {}


def _truthy_claim(value: object) -> bool:
    return value is True or value == 'true' or value == 1 or value == '1'


def microsoft_email_trustworthy(*, tenant: str | None, id_token_claims: dict) -> bool:
    tenant_norm = (tenant or 'common').strip().lower()
    if tenant_norm and tenant_norm != 'common':
        return True
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
        return _truthy_claim(info.get('email_verified')), None, None

    if policy == 'microsoft_tenant':
        if not microsoft_email_trustworthy(tenant=tenant, id_token_claims=claims):
            return False, (
                'Microsoft sign-in requires a verified work account or a company-configured tenant. '
                'Ask your administrator to restrict sign-in to your organization tenant.'
            ), None
        ms_email = info.get('mail') or info.get('userPrincipalName') or info.get('email')
        if isinstance(ms_email, str) and ms_email.strip() and '@' in ms_email:
            return True, None, ms_email.strip().lower()
        return False, None, None

    if policy in {'oidc_email_verified_or_uid_only', 'oauth2_email_verified_or_uid_only'}:
        if _truthy_claim(info.get('email_verified')):
            return True, None, None
        if _truthy_claim(claims.get('email_verified')):
            return True, None, None
        return False, None, None

    return False, None, None


def extract_oauth_profile(
    provider: str,
    userinfo: dict,
    access_token: str,
    *,
    tenant: str | None = None,
    id_token_claims: dict | None = None,
) -> tuple[OAuthProfile | None, str | None]:
    key = str(provider).strip().lower()
    entry = resolve_catalog_slug(key)
    policy = entry.email_link_policy if entry is not None else 'uid_only'
    social_account_provider = entry.allauth_id if entry is not None else key
    info = userinfo if isinstance(userinfo, dict) else {}
    claims = id_token_claims if isinstance(id_token_claims, dict) else {}

    provider_id = str(
        info.get('id')
        or info.get('sub')
        or info.get('userPrincipalName')
        or info.get('mail')
        or ''
    ).strip()
    if not provider_id:
        return None, 'OAuth provider did not return a user id.'

    email = info.get('email') or info.get('mail') or info.get('userPrincipalName')
    full_name = info.get('name') or info.get('displayName') or ''
    email_verified_for_link, policy_error, email_override = _email_verified_for_link_from_policy(
        policy=policy,
        provider_key=social_account_provider,
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
        email = f'{provider_id}@{social_account_provider}.local'
    else:
        email = str(email).strip().lower()

    if not full_name:
        full_name = email.split('@')[0]

    avatar_url = info.get('avatar_url') or info.get('picture') or info.get('photo')
    if not isinstance(avatar_url, str) or not avatar_url.strip():
        avatar_url = None

    return OAuthProfile(
        provider_id=provider_id,
        email=email,
        full_name=str(full_name),
        avatar_url=avatar_url,
        email_verified_for_link=email_verified_for_link,
        userinfo=info,
    ), None


def resolve_oauth_user(*, provider: str, profile: OAuthProfile) -> tuple[User | None, bool, str | None]:
    """
    Link by (provider, uid) first. Link by email only when ``email_verified_for_link`` is true.
    """
    key = str(provider).strip().lower()
    entry = resolve_catalog_slug(key)
    social_key = entry.allauth_id if entry is not None else key
    existing = (
        SocialAccount.objects.filter(provider=social_key, uid=profile.provider_id)
        .select_related('user')
        .first()
    )
    if existing is not None:
        return existing.user, False, None

    synthetic = profile.email.endswith(f'@{social_key}.local')
    if not profile.email_verified_for_link and not synthetic:
        return None, False, (
            'We could not verify your email with this sign-in provider. '
            'Use another sign-in method or contact your administrator.'
        )

    if synthetic:
        user = User.objects.create(
            username=f'{social_key}_{profile.provider_id}',
            email=profile.email,
            first_name=profile.full_name.split(' ')[0],
            last_name=' '.join(profile.full_name.split(' ')[1:]),
        )
        user.set_unusable_password()
        user.save()
        return user, True, None

    user, created = get_or_create_user_for_oauth(
        email=profile.email,
        defaults={
            'username': f'{social_key}_{profile.provider_id}',
            'first_name': profile.full_name.split(' ')[0],
            'last_name': ' '.join(profile.full_name.split(' ')[1:]),
        },
    )
    if not created:
        _backfill_user_names_from_profile(user, profile)

    return user, created, None
