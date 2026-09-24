"""Register identity-service domain events (``identity.*`` prefix)."""

from apps.actions.registry import DomainEventType, EventFieldDoc, register_event

_USER = (
    EventFieldDoc('user_id', 'Internal user primary key', 42),
    EventFieldDoc('email', 'Primary email when available', 'ada@acme.com'),
    EventFieldDoc('username', 'Login username', 'ada@acme.com'),
    EventFieldDoc('source', 'Provisioning channel', 'scim'),
)

_GROUP = (
    EventFieldDoc('group_id', 'CompanyGroup primary key', 7),
    EventFieldDoc('display_name', 'Group display name', 'Engineering'),
    EventFieldDoc('source', 'Group source (manual or scim)', 'scim'),
    EventFieldDoc('external_id', 'SCIM externalId when set', None),
)

register_event(
    DomainEventType(
        id='identity.user.provisioned',
        label='User provisioned',
        description='A user was added or enabled for the company (for example via SCIM).',
        payload_fields=_USER,
        email_subject_template='[Shellui] User provisioned: {{ data.email|default:"user" }}',
        email_payload_email_field='email',
    )
)

register_event(
    DomainEventType(
        id='identity.user.deprovisioned',
        label='User deprovisioned',
        description='Company access was disabled for a user (SCIM deprovision; user is not deleted).',
        payload_fields=_USER,
        email_subject_template='[Shellui] User deprovisioned: {{ data.email|default:"user" }}',
        email_payload_email_field='email',
    )
)

register_event(
    DomainEventType(
        id='identity.user.updated',
        label='User updated',
        description='User profile or SCIM attributes changed. Noisy; not emitted by default.',
        payload_fields=_USER
        + (EventFieldDoc('changed_fields', 'List of changed attribute names', ['displayName']),),
        emit_by_default=False,
        email_subject_template='[Shellui] User updated: {{ data.email|default:"user" }}',
        email_payload_email_field='email',
    )
)

register_event(
    DomainEventType(
        id='identity.group.created',
        label='Group created',
        description='A company group was created.',
        payload_fields=_GROUP,
        email_subject_template='[Shellui] Group created: {{ data.display_name }}',
    )
)

register_event(
    DomainEventType(
        id='identity.group.updated',
        label='Group updated',
        description='Group metadata (display name, external id) changed.',
        payload_fields=_GROUP
        + (EventFieldDoc('changed_fields', 'Changed fields', ['display_name']),),
        email_subject_template='[Shellui] Group updated: {{ data.display_name }}',
    )
)

register_event(
    DomainEventType(
        id='identity.group.deleted',
        label='Group deleted',
        description='A company group was removed.',
        payload_fields=_GROUP,
        email_subject_template='[Shellui] Group deleted: {{ data.display_name }}',
    )
)

register_event(
    DomainEventType(
        id='identity.group.membership_changed',
        label='Group membership changed',
        description='Direct members or nested groups on a group were added or removed.',
        payload_fields=_GROUP
        + (
            EventFieldDoc('change', 'Summary of change', 'members_replaced'),
            EventFieldDoc('user_ids', 'Affected user ids when applicable', [1, 2]),
            EventFieldDoc('nested_group_ids', 'Affected nested group ids', []),
        ),
        email_subject_template='[Shellui] Group membership changed: {{ data.display_name }}',
    )
)

register_event(
    DomainEventType(
        id='identity.scim.token.created',
        label='SCIM token created',
        description='A new SCIM bearer token was issued for the company.',
        payload_fields=(
            EventFieldDoc('token_id', 'Token UUID', '00000000-0000-0000-0000-000000000001'),
            EventFieldDoc('name', 'Operator label for the token', 'Okta prod'),
            EventFieldDoc('token_prefix', 'First characters shown in admin', 'abc123'),
        ),
        email_subject_template='[Shellui] SCIM token created: {{ data.name|default:data.token_prefix }}',
    )
)

register_event(
    DomainEventType(
        id='identity.scim.token.revoked',
        label='SCIM token revoked',
        description='A SCIM bearer token was revoked.',
        payload_fields=(
            EventFieldDoc('token_id', 'Token UUID', '00000000-0000-0000-0000-000000000001'),
            EventFieldDoc('name', 'Operator label', 'Okta prod'),
            EventFieldDoc('token_prefix', 'Prefix shown in admin', 'abc123'),
        ),
        email_subject_template='[Shellui] SCIM token revoked: {{ data.name|default:data.token_prefix }}',
    )
)

register_event(
    DomainEventType(
        id='identity.scim.provisioning_conflict',
        label='SCIM provisioning conflict',
        description='SCIM returned HTTP 409 (for example displayName collision).',
        payload_fields=(
            EventFieldDoc('display_name', 'Requested display name', 'Engineering'),
            EventFieldDoc('operation', 'create or rename', 'create'),
            EventFieldDoc('conflicting_group_id', 'Existing group id', 3),
            EventFieldDoc('conflicting_group_source', 'manual or scim', 'manual'),
            EventFieldDoc('http_status', 'HTTP status recorded', 409),
            EventFieldDoc('channel', 'Provisioning channel', 'scim'),
        ),
        email_subject_template='[Shellui] SCIM provisioning conflict: {{ data.display_name }}',
    )
)
