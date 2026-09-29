"""Record SCIM provisioning signals for operators (logs + durable events)."""

from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from apps.actions.scim_hooks import emit_scim_provisioning_conflict
from apps.companies.models import Company, CompanyGroup
from apps.scim.models import CompanyScimProvisioningState, CompanyScimToken, ScimProvisioningEvent

logger = logging.getLogger(__name__)

OPERATION_CREATE = 'create'
OPERATION_RENAME = 'rename'

HTTP_STATUS_CONFLICT = 409


def _conflict_detail(
    *,
    display_name: str,
    operation: str,
    conflict: CompanyGroup,
) -> dict:
    return {
        'display_name': display_name,
        'operation': operation,
        'conflicting_group_id': conflict.pk,
        'conflicting_group_source': conflict.source,
        'http_status': HTTP_STATUS_CONFLICT,
    }


def record_group_display_name_conflict(
    *,
    company: Company,
    display_name: str,
    conflict: CompanyGroup,
    channel: str,
    operation: str,
    scim_token: CompanyScimToken | None = None,
) -> ScimProvisioningEvent:
    detail = _conflict_detail(
        display_name=(display_name or '').strip(),
        operation=operation,
        conflict=conflict,
    )
    logger.warning(
        'group_display_name_conflict company_id=%s display_name=%r conflicting_group_id=%s '
        'conflicting_group_source=%s channel=%s operation=%s http_status=%s scim_token_id=%s',
        company.pk,
        detail['display_name'],
        detail['conflicting_group_id'],
        detail['conflicting_group_source'],
        channel,
        operation,
        HTTP_STATUS_CONFLICT,
        str(scim_token.pk) if scim_token is not None else None,
    )
    with transaction.atomic():
        event = ScimProvisioningEvent.objects.create(
            company=company,
            event_type=ScimProvisioningEvent.TYPE_GROUP_DISPLAY_NAME_CONFLICT,
            channel=channel,
            scim_token=scim_token,
            detail=detail,
        )
        state, _created = CompanyScimProvisioningState.objects.get_or_create(company=company)
        state.last_error_at = timezone.now()
        state.last_error_code = HTTP_STATUS_CONFLICT
        state.last_error_type = ScimProvisioningEvent.TYPE_GROUP_DISPLAY_NAME_CONFLICT
        state.last_error_detail = detail
        state.save(
            update_fields=[
                'last_error_at',
                'last_error_code',
                'last_error_type',
                'last_error_detail',
            ]
        )
        emit_scim_provisioning_conflict(company, detail=detail, channel=channel)
    return event


def last_provisioning_error_payload(company: Company) -> dict | None:
    state = CompanyScimProvisioningState.objects.filter(company=company).first()
    if state is None or state.last_error_at is None:
        return None
    return {
        'at': state.last_error_at,
        'code': state.last_error_code,
        'type': state.last_error_type,
        'detail': state.last_error_detail,
    }


def recent_provisioning_events_payload(company: Company, *, limit: int = 5) -> list[dict]:
    rows = ScimProvisioningEvent.objects.filter(company=company).order_by('-created_at')[:limit]
    return [
        {
            'id': row.pk,
            'type': row.event_type,
            'channel': row.channel,
            'created_at': row.created_at,
            'detail': row.detail,
        }
        for row in rows
    ]
