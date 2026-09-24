"""Payload builders for identity domain events."""

from __future__ import annotations

from django.contrib.auth import get_user_model

from apps.companies.models import CompanyGroup
from apps.scim.models import CompanyScimToken

User = get_user_model()


def user_event_payload(user, *, source: str = 'scim') -> dict:
    email = (getattr(user, 'email', None) or '').strip()
    username = (getattr(user, 'username', None) or '').strip()
    return {
        'user_id': user.pk,
        'email': email or None,
        'username': username or None,
        'source': source,
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
