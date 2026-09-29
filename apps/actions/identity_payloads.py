"""Payload builders for identity domain events."""

from __future__ import annotations

from django.contrib.auth import get_user_model

from apps.authapi.models import UserPreference
from apps.companies.models import CompanyGroup
from apps.scim.models import CompanyScimToken

User = get_user_model()


def _user_preference_fields(user) -> dict[str, str]:
    """Shellui user preferences (``UserPreference``), with model defaults when unset."""
    try:
        preference = user.preference
    except UserPreference.DoesNotExist:
        return {
            'language': UserPreference.LANGUAGE_EN,
            'region': 'UTC',
        }
    return {
        'language': preference.language,
        'region': preference.region,
    }


def user_event_payload(user, *, source: str = 'scim') -> dict:
    email = (getattr(user, 'email', None) or '').strip()
    username = (getattr(user, 'username', None) or '').strip()
    prefs = _user_preference_fields(user)
    return {
        'user_id': user.pk,
        'email': email or None,
        'username': username or None,
        'source': source,
        'language': prefs['language'],
        'region': prefs['region'],
    }


def group_event_payload(group: CompanyGroup) -> dict:
    return {
        'group_id': group.pk,
        'display_name': group.display_name,
        'source': group.source,
        'external_id': group.scim_external_id or None,
    }


def scim_token_payload(token: CompanyScimToken) -> dict:
    return {
        'token_id': str(token.pk),
        'name': token.name or '',
        'token_prefix': token.token_prefix,
    }


def provisioning_conflict_payload(*, detail: dict, channel: str) -> dict:
    return {
        'display_name': detail.get('display_name'),
        'operation': detail.get('operation'),
        'conflicting_group_id': detail.get('conflicting_group_id'),
        'conflicting_group_source': detail.get('conflicting_group_source'),
        'http_status': detail.get('http_status'),
        'channel': channel,
    }
