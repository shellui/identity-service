"""In-code catalog of domain events (stable ids, labels, payload documentation)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EventFieldDoc:
    name: str
    description: str
    example: Any = None


@dataclass(frozen=True)
class DomainEventType:
    id: str
    label: str
    description: str
    payload_fields: tuple[EventFieldDoc, ...] = ()
    email_context_fields: tuple[EventFieldDoc, ...] = ()
    emit_by_default: bool = True
    email_subject_template: str = ''
    email_payload_email_field: str | None = None

    def __post_init__(self) -> None:
        if not self.email_subject_template:
            object.__setattr__(self, 'email_subject_template', self.label)


_REGISTRY: dict[str, DomainEventType] = {}


def register_event(event: DomainEventType) -> DomainEventType:
    if event.id in _REGISTRY:
        raise ValueError(f'Duplicate event type registration: {event.id!r}')
    _REGISTRY[event.id] = event
    return event


def get_event_type(event_id: str) -> DomainEventType:
    try:
        return _REGISTRY[event_id]
    except KeyError as exc:
        raise ValueError(f'Unknown event type: {event_id!r}') from exc


def is_registered_event(event_id: str) -> bool:
    return event_id in _REGISTRY


def all_event_types() -> list[DomainEventType]:
    return sorted(_REGISTRY.values(), key=lambda e: e.id)


SHARED_EMAIL_ENVELOPE_FIELDS: tuple[EventFieldDoc, ...] = (
    EventFieldDoc(
        'envelope.id',
        'Unique envelope id (idempotency key for webhooks)',
        '550e8400-e29b-41d4-a716-446655440000',
    ),
    EventFieldDoc('envelope.type', 'Event type id', 'identity.user.created'),
    EventFieldDoc('envelope.time', 'ISO8601 event time', '2026-09-24T13:30:00+00:00'),
    EventFieldDoc('envelope.company.id', 'Company primary key', 1),
    EventFieldDoc('envelope.company.slug', 'Company slug', 'acme'),
    EventFieldDoc('envelope.company.name', 'Company display name', 'Acme'),
)


def event_field_doc_dict(field: EventFieldDoc) -> dict:
    return {
        'name': field.name,
        'description': field.description,
        'example': field.example,
    }


def event_choices() -> list[tuple[str, str]]:
    return [
        (
            e.id,
            f'{e.label} ({e.id})'
            + (' — not emitted yet' if not e.emit_by_default else ''),
        )
        for e in all_event_types()
    ]
