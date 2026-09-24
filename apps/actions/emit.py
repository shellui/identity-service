"""Single entry point for domain event emission."""

from __future__ import annotations

from typing import Any

from apps.actions.delivery import schedule_outbox_delivery
from apps.actions.envelope import build_envelope
from apps.actions.models import ActionOutbox, ActionRule
from apps.actions.registry import get_event_type
from apps.companies.models import Company


def emit_event(
    event_type: str,
    company: Company,
    payload: dict[str, Any],
    *,
    actor: dict[str, Any] | None = None,
    force: bool = False,
) -> list[ActionOutbox]:
    """
    Validate ``event_type``, match enabled ``ActionRule`` rows for ``company``, write outbox rows.

    Schedules a best-effort delivery attempt after the surrounding database transaction commits.
    """
    event = get_event_type(event_type)
    if not event.emit_by_default and not force:
        return []

    rules = list(
        ActionRule.objects.filter(
            company=company,
            event_type=event_type,
            enabled=True,
        ).order_by('pk')
    )
    if not rules:
        return []

    envelope = build_envelope(
        event_type=event_type,
        company=company,
        data=dict(payload),
        actor=actor,
    )
    outbox_rows: list[ActionOutbox] = []
    for rule in rules:
        outbox_rows.append(
            ActionOutbox.objects.create(
                company=company,
                action_rule=rule,
                event_type=event_type,
                envelope=envelope,
            )
        )
    schedule_outbox_delivery([row.pk for row in outbox_rows])
    return outbox_rows


def emit_event_if_rules(
    event_type: str,
    company: Company,
    payload: dict[str, Any],
    *,
    actor: dict[str, Any] | None = None,
    force: bool = False,
) -> list[ActionOutbox]:
    """Like ``emit_event`` but skips unknown types and swallows errors (for hot paths)."""
    try:
        return emit_event(event_type, company, payload, actor=actor, force=force)
    except ValueError:
        return []
