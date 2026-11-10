"""MCP admin operation summaries. Consumed by ``openapi_admin``."""
from __future__ import annotations
from typing import NamedTuple
from apps.authapi.mcp_openapi import mcp_tool

class _McpSpec(NamedTuple):
    summary: str
    lead: str
    side_effects: str
    sends_email: bool = False
    destructive: bool = False
    sensitive: bool = False
    read_only: bool = True
    notes: str = ''

MCP_SPECS: dict[str, _McpSpec] = {
    'identity_list_users': _McpSpec(
        'List company users',
        'Paginated directory of users in the token company.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_get_users': _McpSpec(
        'Read one company user',
        'Returns profile fields and company membership metadata.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_replace_users': _McpSpec(
        'Update a company user',
        'Updates names, enabled state, manual groups, and cached metadata.',
        'May update user, membership, and group rows.',
        sensitive=True, read_only=False,
    ),
    'identity_delete_users': _McpSpec(
        'Remove user from company',
        'Removes membership and may delete the account when it was their last company.',
        'Deletes membership or user rows.',
        destructive=True, sensitive=True, read_only=False,
    ),
    'identity_get_users_audience': _McpSpec(
        'Evaluate user audience filters',
        'Counts users matching broadcast-style audience JSON without sending mail.',
        'Read-only evaluation.',
        sensitive=True,
    ),
    'identity_list_groups': _McpSpec(
        'List company groups',
        'Returns manual and SCIM groups with member counts.',
        'Read-only.',
    ),
    'identity_create_groups': _McpSpec(
        'Create a manual group',
        'Creates a company-owned group with a display name.',
        'Inserts a group row.',
        read_only=False,
    ),
    'identity_get_groups': _McpSpec(
        'Read one company group',
        'Returns group metadata and member count.',
        'Read-only.',
    ),
    'identity_replace_groups': _McpSpec(
        'Rename a manual group',
        'Replaces the group display name.',
        'Updates the group row.',
        read_only=False,
    ),
    'identity_update_groups': _McpSpec(
        'Patch a manual group',
        'Same as PUT rename for manual groups.',
        'Updates the group row.',
        read_only=False,
    ),
    'identity_delete_groups': _McpSpec(
        'Delete a manual group',
        'Deletes a manual group that is not SCIM-managed.',
        'Removes the group row.',
        destructive=True, read_only=False,
    ),
    'identity_list_oauth_clients': _McpSpec(
        'List OAuth client mappings',
        'Lists company OAuth client rows linked to SocialApp keys.',
        'Read-only.',
    ),
    'identity_create_oauth_clients': _McpSpec(
        'Attach an OAuth client mapping',
        'Links an existing company SocialApp to the company OAuth client table.',
        'Inserts a mapping row.',
        read_only=False,
    ),
    'identity_get_oauth_clients': _McpSpec(
        'Read one OAuth client mapping',
        'Returns provider, SocialApp id, and active flag.',
        'Read-only.',
    ),
    'identity_replace_oauth_clients': _McpSpec(
        'Update OAuth client mapping',
        'Patches the active flag or linked SocialApp when allowed.',
        'Updates mapping row.',
        read_only=False,
    ),
    'identity_delete_oauth_clients': _McpSpec(
        'Delete OAuth client mapping',
        'Removes the mapping; does not delete the SocialApp.',
        'Deletes mapping row.',
        destructive=True, read_only=False,
    ),
    'identity_list_oauth_redirects': _McpSpec(
        'List OAuth redirect URIs',
        'Returns redirect allowlist rows for the company.',
        'Read-only.',
    ),
    'identity_create_oauth_redirects': _McpSpec(
        'Create OAuth redirect URI',
        'Adds a redirect URI to the company allowlist.',
        'Inserts redirect row.',
        read_only=False,
    ),
    'identity_get_oauth_redirects': _McpSpec(
        'Read one OAuth redirect URI',
        'Returns one redirect row.',
        'Read-only.',
    ),
    'identity_update_oauth_redirects': _McpSpec(
        'Update OAuth redirect URI',
        'Patches redirect URI or enabled flag.',
        'Updates redirect row.',
        read_only=False,
    ),
    'identity_delete_oauth_redirects': _McpSpec(
        'Delete OAuth redirect URI',
        'Removes a redirect from the allowlist.',
        'Deletes redirect row.',
        destructive=True, read_only=False,
    ),
    'identity_list_oauth_social_apps': _McpSpec(
        'List company OAuth SocialApps',
        'Lists SocialApp keys owned by the company.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_create_oauth_social_apps': _McpSpec(
        'Create OAuth SocialApp key',
        'Creates django-allauth SocialApp credentials for a provider.',
        'Inserts SocialApp row with encrypted secret.',
        sensitive=True, read_only=False,
    ),
    'identity_replace_oauth_social_apps': _McpSpec(
        'Update OAuth SocialApp key',
        'Updates client id, secret, or provider settings.',
        'Persists SocialApp fields.',
        sensitive=True, read_only=False,
    ),
    'identity_delete_oauth_social_apps': _McpSpec(
        'Delete OAuth SocialApp key',
        'Deletes the SocialApp when not referenced by active clients.',
        'Removes SocialApp row.',
        destructive=True, sensitive=True, read_only=False,
    ),
    'identity_get_oauth_provider_catalog': _McpSpec(
        'Read OAuth provider catalog',
        'Returns supported providers, callback URLs, and setup metadata.',
        'Read-only.',
    ),
    'identity_replace_hosting_oauth_redirects': _McpSpec(
        'Sync hosting OAuth redirects',
        'Replaces auto-managed redirect URIs from hosting integration.',
        'Updates redirect rows.',
        read_only=False,
    ),
    'identity_delete_hosting_oauth_redirects': _McpSpec(
        'Remove hosting OAuth redirects',
        'Deletes hosting-managed redirect URIs for the company.',
        'Deletes redirect rows.',
        destructive=True, read_only=False,
    ),
    'identity_get_auth_methods': _McpSpec(
        'Read enabled auth methods',
        'Returns magic link, OAuth, and SAML toggles for the company.',
        'Read-only.',
    ),
    'identity_update_auth_methods': _McpSpec(
        'Patch auth methods',
        'Updates which sign-in methods are enabled.',
        'Updates company auth settings.',
        read_only=False,
    ),
    'identity_replace_auth_methods': _McpSpec(
        'Replace auth methods',
        'Replaces the auth methods configuration object.',
        'Updates company auth settings.',
        read_only=False,
    ),
    'identity_get_scim_status': _McpSpec(
        'Read SCIM provisioning status',
        'Returns whether SCIM is enabled and base URL hints.',
        'Read-only.',
    ),
    'identity_list_scim_tokens': _McpSpec(
        'List SCIM bearer tokens',
        'Lists active SCIM tokens with metadata (not plaintext).',
        'Read-only.',
        sensitive=True,
    ),
    'identity_create_scim_tokens': _McpSpec(
        'Create a SCIM bearer token. The secret is shown once in admin, not to the agent.',
        'Mints a SCIM token. The plaintext is shown once on the admin HTTP response and is masked in the MCP result.',
        'Inserts SCIM token row.',
        sensitive=True, read_only=False,
    ),
    'identity_revoke_scim_tokens': _McpSpec(
        'Revoke SCIM bearer token',
        'Revokes a SCIM token immediately.',
        'Updates token revoked timestamp.',
        destructive=True, sensitive=True, read_only=False,
    ),
    'identity_list_personal_access_tokens': _McpSpec(
        'List personal access tokens',
        'Lists PAT metadata for the authenticated user in the company.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_create_personal_access_tokens': _McpSpec(
        'Create a personal access token. The JWT is shown once in admin, not to the agent.',
        'Mints a PAT. The JWT is shown once on the admin HTTP response and is masked in the MCP result.',
        'Inserts PAT row.',
        sensitive=True, read_only=False,
    ),
    'identity_revoke_personal_access_tokens': _McpSpec(
        'Revoke personal access token',
        'Revokes one PAT by id.',
        'Updates PAT revoked timestamp.',
        destructive=True, sensitive=True, read_only=False,
    ),
    'identity_list_companies': _McpSpec(
        'List member companies',
        'Companies where the caller is a member.',
        'Read-only.',
    ),
    'identity_get_companies': _McpSpec(
        'Read company settings',
        'Returns company name, owners, and join access settings.',
        'Read-only.',
    ),
    'identity_replace_companies': _McpSpec(
        'Replace company settings',
        'Updates name, owners, join access, and desktop redirect settings.',
        'Updates company row.',
        read_only=False,
    ),
    'identity_update_companies': _McpSpec(
        'Patch company settings',
        'Partial update of company settings.',
        'Updates company row.',
        read_only=False,
    ),
    'identity_list_invitations': _McpSpec(
        'List open invitations',
        'Pending and blocking revoked invitations for the company.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_create_invitations': _McpSpec(
        'Invite a user by email',
        'Creates a pending invitation and sends email or webhook event.',
        'Inserts invitation row.',
        sends_email=True, sensitive=True, read_only=False,
    ),
    'identity_delete_invitations': _McpSpec(
        'Delete an invitation row',
        'Hard-deletes an invitation record.',
        'Deletes invitation row.',
        destructive=True, sensitive=True, read_only=False,
    ),
    'identity_revoke_invitations': _McpSpec(
        'Revoke a pending invitation',
        'Marks invitation revoked so sign-in is blocked.',
        'Updates invitation status.',
        sensitive=True, read_only=False,
    ),
    'identity_list_events': _McpSpec(
        'List identity event log',
        'Paginated audit events for the company.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_get_events': _McpSpec(
        'Read one event log row',
        'Returns full event payload for one row.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_list_events_types': _McpSpec(
        'List event log types',
        'Catalog types stored in the event log.',
        'Read-only.',
    ),
    'identity_get_events_retention': _McpSpec(
        'Read event log retention',
        'Returns configured retention and stale flag.',
        'Read-only.',
    ),
    'identity_list_action_events': _McpSpec(
        'List Actions event types',
        'Domain events available for webhook rules.',
        'Read-only.',
    ),
    'identity_list_action_rules': _McpSpec(
        'List Actions webhook rules',
        'Signed HTTPS webhook rules for identity domain events.',
        'Read-only.',
    ),
    'identity_create_action_rules': _McpSpec(
        'Create an Actions webhook rule. The signing secret is shown once in admin, not to the agent.',
        'Creates a webhook rule. The signing secret is shown once on the admin HTTP response and is masked in the MCP result.',
        'Inserts rule with encrypted secret.',
        sensitive=True, read_only=False,
    ),
    'identity_get_action_rules': _McpSpec(
        'Read one Actions webhook rule',
        'Returns rule metadata without plaintext secret.',
        'Read-only.',
    ),
    'identity_update_action_rules': _McpSpec(
        'Update Actions webhook rule',
        'Patches URL, enabled flag, or filters.',
        'Updates rule row.',
        read_only=False,
    ),
    'identity_delete_action_rules': _McpSpec(
        'Delete Actions webhook rule',
        'Deletes the webhook rule.',
        'Removes rule row.',
        destructive=True, read_only=False,
    ),
    'identity_rotate_rule_secret': _McpSpec(
        'Rotate a webhook signing secret. The new secret is shown once in admin, not to the agent.',
        'Issues a new HMAC secret. It is shown once on the admin HTTP response and is masked in the MCP result.',
        'Updates encrypted secret.',
        sensitive=True, read_only=False,
    ),
    'identity_send_test_rule': _McpSpec(
        'Send test webhook delivery',
        'Enqueues a synthetic event to the rule URL.',
        'Inserts outbox delivery row.',
        read_only=False,
    ),
    'identity_list_action_deliveries': _McpSpec(
        'List webhook deliveries',
        'Recent webhook outbox rows for the company.',
        'Read-only.',
    ),
    'identity_get_action_deliveries': _McpSpec(
        'Read one webhook delivery',
        'Returns attempts and envelope payload.',
        'Read-only.',
    ),
    'identity_requeue_action_deliveries': _McpSpec(
        'Requeue failed webhook delivery',
        'Resets a failed delivery to pending.',
        'Updates outbox status.',
        read_only=False,
    ),
    'identity_list_services': _McpSpec(
        'List Shellui MCP service URLs',
        'Returns connected Shellui service MCP endpoints for agents.',
        'Read-only.',
    ),
}

for _op_id, _spec in MCP_SPECS.items():
    mcp_tool(
        operation_id=_op_id,
        read_only=_spec.read_only,
        destructive=_spec.destructive,
        sensitive=_spec.sensitive,
    )
