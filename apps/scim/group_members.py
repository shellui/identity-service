"""Parse SCIM Group members payloads (User + Group)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedScimMembers:
    user_ids: list[int]
    group_ids: list[int]


def parse_scim_members(members) -> ParsedScimMembers:
    user_ids: list[int] = []
    group_ids: list[int] = []
    for entry in members or []:
        if not isinstance(entry, dict):
            continue
        raw = entry.get('value')
        if raw is None or raw == '':
            continue
        member_type = (entry.get('type') or 'User').strip().lower()
        member_id = int(raw)
        if member_type == 'group':
            group_ids.append(member_id)
        else:
            user_ids.append(member_id)
    return ParsedScimMembers(user_ids=user_ids, group_ids=group_ids)
