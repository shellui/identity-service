"""Register identity-service domain events (``identity.*`` prefix)."""

from apps.actions.registry import DomainEventType, EventFieldDoc, register_event

_USER = (
    EventFieldDoc('user_id', 'Internal user primary key', 42),
    EventFieldDoc('email', 'Primary email when available', 'ada@acme.com'),
    EventFieldDoc('username', 'Login username', 'ada@acme.com'),
    EventFieldDoc('source', 'Channel: oauth, admin, self, scim, …', 'oauth'),
    EventFieldDoc(
        'language',
        'User UI language from UserPreference (e.g. en, fr)',
        'en',
    ),
    EventFieldDoc(
        'region',
        'User region / timezone preference from UserPreference',
        'Europe/Paris',
    ),
)

_INVITATION = (
    EventFieldDoc('invitation_id', 'Invitation primary key', 7),
    EventFieldDoc('email', 'Invited email (lowercase)', 'ada@acme.com'),
    EventFieldDoc('language', 'Invitation email language (en, fr)', 'fr'),
    EventFieldDoc('invited_by', 'Email of the admin who sent the invitation', 'grace@acme.com'),
    EventFieldDoc(
        'invitation_url',
        'App URL the invitation links to (not a sign-in credential); null when not provided',
        'https://app.acme.com/',
    ),
    EventFieldDoc('source', 'Always invitation', 'invitation'),
)

_ACCOUNT_USER = _USER + (
    EventFieldDoc('oauth_provider', 'OAuth provider id when source=oauth', 'github'),
)

register_event(
    DomainEventType(
        id='identity.scim.user.provisioned',
        label='SCIM user provisioned',
        description='Company access was enabled for a user via SCIM (create or re-enable). The user account may already exist.',
        payload_fields=_USER,
    )
)

register_event(
    DomainEventType(
        id='identity.scim.user.deprovisioned',
        label='SCIM user deprovisioned',
        description='Company access was disabled via SCIM (deprovision). The user account is not deleted.',
        payload_fields=_USER,
    )
)

register_event(
    DomainEventType(
        id='identity.user.created',
        label='User account created',
        description='A new Django user row was created (OAuth first sign-in or admin), scoped to the company in context.',
        payload_fields=_ACCOUNT_USER,
    )
)

register_event(
    DomainEventType(
        id='identity.user.invited',
        label='User invited',
        description=(
            'A company owner or staff member invited someone by email. No account is created yet: '
            'the invitee gets access on their first sign-in with that email. When the company has an '
            'enabled webhook rule for this event, identity-service skips its own invitation email.'
        ),
        payload_fields=_INVITATION,
    )
)

register_event(
    DomainEventType(
        id='identity.user.invitation_revoked',
        label='User invitation revoked',
        description=(
            'A company owner or staff member revoked a pending invitation. Sign-in with that email is '
            'refused for this company until a new invitation is sent.'
        ),
        payload_fields=_INVITATION
        + (EventFieldDoc('revoked_by', 'Email of the admin who revoked the invitation', 'grace@acme.com'),),
    )
)

register_event(
    DomainEventType(
        id='identity.user.deleted',
        label='User account deleted',
        description='The user account was permanently deleted. Emitted once per company membership before removal.',
        payload_fields=_USER,
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
    )
)

_GROUP = (
    EventFieldDoc('group_id', 'CompanyGroup primary key', 7),
    EventFieldDoc('display_name', 'Group display name', 'Engineering'),
    EventFieldDoc('source', 'Group source (manual or scim)', 'scim'),
    EventFieldDoc('external_id', 'SCIM externalId when set', None),
)

register_event(
    DomainEventType(
        id='identity.group.created',
        label='Group created',
        description='A company group was created.',
        payload_fields=_GROUP,
    )
)

register_event(
    DomainEventType(
        id='identity.group.updated',
        label='Group updated',
        description='Group metadata (display name, external id) changed.',
        payload_fields=_GROUP
        + (EventFieldDoc('changed_fields', 'Changed fields', ['display_name']),),
    )
)

register_event(
    DomainEventType(
        id='identity.group.deleted',
        label='Group deleted',
        description='A company group was removed.',
        payload_fields=_GROUP,
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
    )
)

register_event(
    DomainEventType(
        id='identity.auth.magic_link.requested',
        label='Magic link requested',
        description=(
            'A user requested a passwordless email sign-in link for this company. '
            'Notification only: the payload has request_id and expires_at but never the sign-in '
            'link or token. Identity always sends the sign-in email itself.'
        ),
        payload_fields=_USER
        + (
            EventFieldDoc('request_id', 'Magic link request UUID', '00000000-0000-0000-0000-000000000001'),
            EventFieldDoc('expires_at', 'ISO8601 expiry for the link', '2026-09-25T10:00:00+00:00'),
        ),
        # Never sent or stored. Kept here so a future caller cannot leak them by mistake.
        sensitive_fields=('magic_link_url', 'token', 'raw_token'),
    )
)

_LOGIN = (
    EventFieldDoc('provider', 'Sign-in method (github, google, saml, magic_link, django_admin, …)', 'github'),
    EventFieldDoc('is_staff_at_event', 'Present and true when the user was Django staff', True),
    EventFieldDoc('ip_hash', 'Salted SHA-256 of the client IP (raw IP is never stored)', 'b5bb9d80…'),
    EventFieldDoc('user_agent', 'User-Agent, truncated to 512 characters', 'Mozilla/5.0 …'),
    EventFieldDoc('client_timezone', 'IANA timezone sent by the client', 'Europe/Paris'),
    EventFieldDoc('client_device_id_hash', 'Salted SHA-256 of the optional client device id', '7d865e95…'),
    EventFieldDoc('client_country', 'GeoIP country when configured', 'FR'),
    EventFieldDoc('client_city', 'GeoIP city when configured', 'Paris'),
)

register_event(
    DomainEventType(
        id='identity.auth.login.succeeded',
        label='Sign-in succeeded',
        description='A user signed in (OAuth, SAML, magic link, or Django admin). Event log only.',
        payload_fields=_LOGIN,
        webhook=False,
    )
)

register_event(
    DomainEventType(
        id='identity.auth.login.failed',
        label='Sign-in failed',
        description=(
            'A sign-in attempt was refused. The user is linked when it could be resolved. '
            'Event log only: anonymous traffic can trigger it, so it is never sent to webhooks.'
        ),
        payload_fields=_LOGIN
        + (EventFieldDoc('failure_reason', 'Why the sign-in was refused', 'Company access is disabled.'),),
        webhook=False,
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
    )
)
