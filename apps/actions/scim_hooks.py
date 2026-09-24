"""Emit identity action events from SCIM adapters (post-commit via emit_event)."""

from __future__ import annotations

from apps.actions.emit import emit_event_if_rules
from apps.actions.identity_payloads import (
    group_event_payload,
    provisioning_conflict_payload,
    user_event_payload,
)
from apps.companies.models import Company


def emit_user_provisioned(company, user) -> None:
    emit_event_if_rules(
        'identity.user.provisioned',
        company,
        user_event_payload(user, source='scim'),
    )


def emit_user_deprovisioned(company, user) -> None:
    emit_event_if_rules(
        'identity.user.deprovisioned',
        company,
        user_event_payload(user, source='scim'),
    )


def emit_group_created(company, group) -> None:
    emit_event_if_rules('identity.group.created', company, group_event_payload(group))


def emit_group_updated(company, group, *, changed_fields: list[str] | None = None) -> None:
    payload = group_event_payload(group)
    if changed_fields:
        payload['changed_fields'] = changed_fields
    emit_event_if_rules('identity.group.updated', company, payload)


def emit_group_deleted(company, group) -> None:
    emit_event_if_rules('identity.group.deleted', company, group_event_payload(group))


def emit_group_membership_changed(
    company,
    group,
    *,
    change: str,
    user_ids: list[int] | None = None,
    nested_group_ids: list[int] | None = None,
) -> None:
    payload = group_event_payload(group)
    payload['change'] = change
    payload['user_ids'] = user_ids or []
    payload['nested_group_ids'] = nested_group_ids or []
    emit_event_if_rules('identity.group.membership_changed', company, payload)


def emit_scim_provisioning_conflict(company: Company, *, detail: dict, channel: str) -> None:
    emit_event_if_rules(
        'identity.scim.provisioning_conflict',
        company,
        provisioning_conflict_payload(detail=detail, channel=channel),
    )
