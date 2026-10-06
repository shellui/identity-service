"""Write catalog events to the ``EventLog`` table."""

from __future__ import annotations

from typing import Any

from apps.actions.models import EventLog
from apps.actions.registry import DomainEventType

_EMPTY = (None, '', [], {})


def compact_event_data(event: DomainEventType, payload: dict[str, Any]) -> dict[str, Any]:
    """Payload as stored in the log: no empty values, no ``user_id`` (own column), no secrets."""
    skip = {'user_id', *event.sensitive_fields}
    return {k: v for k, v in payload.items() if k not in skip and v not in _EMPTY and v is not False}


def _as_id(raw: Any) -> int | None:
    return raw if isinstance(raw, int) and not isinstance(raw, bool) else None


def _payload_user_id(payload: dict[str, Any]) -> int | None:
    """``user_id``, or the only entry of ``user_ids`` (one-user membership changes)."""
    user_id = _as_id(payload.get('user_id'))
    if user_id is not None:
        return user_id
    user_ids = payload.get('user_ids')
    if isinstance(user_ids, list) and len(user_ids) == 1:
        return _as_id(user_ids[0])
    return None


def record_event(
    event: DomainEventType,
    company,
    payload: dict[str, Any],
    *,
    user=None,
) -> EventLog:
    """Insert one log row. ``user`` defaults to ``payload['user_id']``."""
    return EventLog.objects.create(
        company=company,
        user_id=user.pk if user is not None else _payload_user_id(payload),
        event_type=event.id,
        data=compact_event_data(event, payload),
    )
