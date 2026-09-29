"""OAuth profile extraction and safe user resolution (verified email linking)."""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass

import jwt
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model

User = get_user_model()


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


def extract_oauth_profile(
    provider: str,
    userinfo: dict,
    access_token: str,
    *,
    tenant: str | None = None,
    id_token_claims: dict | None = None,
) -> tuple[OAuthProfile | None, str | None]:
    key = str(provider).strip().lower()
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
    email_verified_for_link = False

    if key == 'google':
        email_verified_for_link = _truthy_claim(info.get('email_verified'))
    elif key == 'github':
        gh_email, verified = _fetch_github_verified_primary_email(access_token)
        if verified and gh_email:
            email = gh_email
            email_verified_for_link = True
        else:
            return None, (
                'GitHub sign-in requires a verified primary email on your account. '
                'Verify your email at GitHub, then try again.'
            )
    elif key == 'microsoft':
        if not microsoft_email_trustworthy(tenant=tenant, id_token_claims=claims):
            return None, (
                'Microsoft sign-in requires a verified work account or a company-configured tenant. '
                'Ask your administrator to restrict sign-in to your organization tenant.'
            )
        ms_email = info.get('mail') or info.get('userPrincipalName') or info.get('email')
        if isinstance(ms_email, str) and ms_email.strip() and '@' in ms_email:
            email = ms_email
            email_verified_for_link = True
        else:
            email_verified_for_link = False
    else:
        email_verified_for_link = _truthy_claim(info.get('email_verified'))

    if not email or not str(email).strip():
        email = f'{provider_id}@{key}.local'
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
    existing = (
        SocialAccount.objects.filter(provider=key, uid=profile.provider_id)
        .select_related('user')
        .first()
    )
    if existing is not None:
        return existing.user, False, None

    synthetic = profile.email.endswith(f'@{key}.local')
    if not profile.email_verified_for_link and not synthetic:
        return None, False, (
            'We could not verify your email with this sign-in provider. '
            'Use another sign-in method or contact your administrator.'
        )

    if synthetic:
        user = User.objects.create(
            username=f'{key}_{profile.provider_id}',
            email=profile.email,
            first_name=profile.full_name.split(' ')[0],
            last_name=' '.join(profile.full_name.split(' ')[1:]),
        )
        user.set_unusable_password()
        user.save()
        return user, True, None

    user = User.objects.filter(email__iexact=profile.email).first()
    created = False
    if user is None:
        created = True
        user = User.objects.create(
            username=f'{key}_{profile.provider_id}',
            email=profile.email,
            first_name=profile.full_name.split(' ')[0],
            last_name=' '.join(profile.full_name.split(' ')[1:]),
        )
        user.set_unusable_password()
        user.save()
    else:
        updates: list[str] = []
        if not user.first_name and profile.full_name:
            user.first_name = profile.full_name.split(' ')[0]
            updates.append('first_name')
        if not user.last_name and ' ' in profile.full_name:
            user.last_name = ' '.join(profile.full_name.split(' ')[1:])
            updates.append('last_name')
        if updates:
            user.save(update_fields=updates)

    return user, created, None
