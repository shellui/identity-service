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
    'api_v1_users_list': _McpSpec(
        'List company users',
        'Paginated directory of users in the token company.',
        'Read-only.',
        sensitive=True,
    ),
    'api_v1_users_retrieve': _McpSpec(
        'Read one company user',
        'Returns profile fields and company membership metadata.',
        'Read-only.',
        sensitive=True,
    ),
    'api_v1_users_update': _McpSpec(
        'Update a company user',
        'Updates names, enabled state, manual groups, and cached metadata.',
        'May update user, membership, and group rows.',
        sensitive=True, read_only=False,
    ),
    'api_v1_users_destroy': _McpSpec(
        'Remove user from company',
        'Removes membership and may delete the account when it was their last company.',
        'Deletes membership or user rows.',
        destructive=True, sensitive=True, read_only=False,
    ),
    'api_v1_users_audience': _McpSpec(
        'Evaluate user audience filters',
        'Counts users matching broadcast-style audience JSON without sending mail.',
        'Read-only evaluation.',
        sensitive=True,
    ),
    'api_v1_groups_list': _McpSpec(
        'List company groups',
        'Returns manual and SCIM groups with member counts.',
        'Read-only.',
    ),
    'api_v1_groups_create': _McpSpec(
        'Create a manual group',
        'Creates a company-owned group with a display name.',
        'Inserts a group row.',
        read_only=False,
    ),
    'api_v1_groups_retrieve': _McpSpec(
        'Read one company group',
        'Returns group metadata and member count.',
        'Read-only.',
    ),
    'api_v1_groups_update': _McpSpec(
        'Rename a manual group',
        'Replaces the group display name.',
        'Updates the group row.',
        read_only=False,
    ),
    'api_v1_groups_partial_update': _McpSpec(
        'Patch a manual group',
        'Same as PUT rename for manual groups.',
        'Updates the group row.',
        read_only=False,
    ),
    'api_v1_groups_destroy': _McpSpec(
        'Delete a manual group',
        'Deletes a manual group that is not SCIM-managed.',
        'Removes the group row.',
        destructive=True, read_only=False,
    ),
    'api_v1_oauth_clients_list': _McpSpec(
        'List OAuth client mappings',
        'Lists company OAuth client rows linked to SocialApp keys.',
        'Read-only.',
    ),
    'api_v1_oauth_clients_create': _McpSpec(
        'Attach an OAuth client mapping',
        'Links an existing company SocialApp to the company OAuth client table.',
        'Inserts a mapping row.',
        read_only=False,
    ),
    'api_v1_oauth_clients_retrieve': _McpSpec(
        'Read one OAuth client mapping',
        'Returns provider, SocialApp id, and active flag.',
        'Read-only.',
    ),
    'api_v1_oauth_clients_update': _McpSpec(
        'Update OAuth client mapping',
        'Patches the active flag or linked SocialApp when allowed.',
        'Updates mapping row.',
        read_only=False,
    ),
    'api_v1_oauth_clients_destroy': _McpSpec(
        'Delete OAuth client mapping',
        'Removes the mapping; does not delete the SocialApp.',
        'Deletes mapping row.',
        destructive=True, read_only=False,
    ),
    'api_v1_oauth_redirects_list': _McpSpec(
        'List OAuth redirect URIs',
        'Returns redirect allowlist rows for the company.',
        'Read-only.',
    ),
    'api_v1_oauth_redirects_create': _McpSpec(
        'Create OAuth redirect URI',
        'Adds a redirect URI to the company allowlist.',
        'Inserts redirect row.',
        read_only=False,
    ),
    'api_v1_oauth_redirects_retrieve': _McpSpec(
        'Read one OAuth redirect URI',
        'Returns one redirect row.',
        'Read-only.',
    ),
    'api_v1_oauth_redirects_partial_update': _McpSpec(
        'Update OAuth redirect URI',
        'Patches redirect URI or enabled flag.',
        'Updates redirect row.',
        read_only=False,
    ),
    'api_v1_oauth_redirects_destroy': _McpSpec(
        'Delete OAuth redirect URI',
        'Removes a redirect from the allowlist.',
        'Deletes redirect row.',
        destructive=True, read_only=False,
    ),
    'api_v1_oauth_social_apps_list': _McpSpec(
        'List company OAuth SocialApps',
        'Lists SocialApp keys owned by the company.',
        'Read-only.',
        sensitive=True,
    ),
    'api_v1_oauth_social_apps_create': _McpSpec(
        'Create OAuth SocialApp key',
        'Creates django-allauth SocialApp credentials for a provider.',
        'Inserts SocialApp row with encrypted secret.',
        sensitive=True, read_only=False,
    ),
    'api_v1_oauth_social_apps_update': _McpSpec(
        'Update OAuth SocialApp key',
        'Updates client id, secret, or provider settings.',
        'Persists SocialApp fields.',
        sensitive=True, read_only=False,
    ),
    'api_v1_oauth_social_apps_destroy': _McpSpec(
        'Delete OAuth SocialApp key',
        'Deletes the SocialApp when not referenced by active clients.',
        'Removes SocialApp row.',
        destructive=True, sensitive=True, read_only=False,
    ),
    'api_v1_oauth_provider_catalog_retrieve': _McpSpec(
        'Read OAuth provider catalog',
        'Returns supported providers, callback URLs, and setup metadata.',
        'Read-only.',
    ),
    'api_v1_hosting_oauth_redirects_update': _McpSpec(
        'Sync hosting OAuth redirects',
        'Replaces auto-managed redirect URIs from hosting integration.',
        'Updates redirect rows.',
        read_only=False,
    ),
    'api_v1_hosting_oauth_redirects_destroy': _McpSpec(
        'Remove hosting OAuth redirects',
        'Deletes hosting-managed redirect URIs for the company.',
        'Deletes redirect rows.',
        destructive=True, read_only=False,
    ),
    'api_v1_auth_methods_retrieve': _McpSpec(
        'Read enabled auth methods',
        'Returns magic link, OAuth, and SAML toggles for the company.',
        'Read-only.',
    ),
    'api_v1_auth_methods_partial_update': _McpSpec(
        'Patch auth methods',
        'Updates which sign-in methods are enabled.',
        'Updates company auth settings.',
        read_only=False,
    ),
    'api_v1_auth_methods_update': _McpSpec(
        'Replace auth methods',
        'Replaces the auth methods configuration object.',
        'Updates company auth settings.',
        read_only=False,
    ),
    'api_v1_scim_status': _McpSpec(
        'Read SCIM provisioning status',
        'Returns whether SCIM is enabled and base URL hints.',
        'Read-only.',
    ),
    'api_v1_scim_tokens_list': _McpSpec(
        'List SCIM bearer tokens',
        'Lists active SCIM tokens with metadata (not plaintext).',
        'Read-only.',
        sensitive=True,
    ),
    'api_v1_scim_tokens_create': _McpSpec(
        'Create SCIM bearer token',
        'Mints a new SCIM token and returns the secret once.',
        'Inserts SCIM token row.',
        sensitive=True, read_only=False,
    ),
    'api_v1_scim_tokens_revoke': _McpSpec(
        'Revoke SCIM bearer token',
        'Revokes a SCIM token immediately.',
        'Updates token revoked timestamp.',
        destructive=True, sensitive=True, read_only=False,
    ),
    'api_v1_personal_access_tokens_list': _McpSpec(
        'List personal access tokens',
        'Lists PAT metadata for the authenticated user in the company.',
        'Read-only.',
        sensitive=True,
    ),
    'api_v1_personal_access_tokens_create': _McpSpec(
        'Create personal access token',
        'Mints a PAT and returns the JWT once in the response.',
        'Inserts PAT row.',
        sensitive=True, read_only=False,
    ),
    'api_v1_personal_access_tokens_revoke': _McpSpec(
        'Revoke personal access token',
        'Revokes one PAT by id.',
        'Updates PAT revoked timestamp.',
        destructive=True, sensitive=True, read_only=False,
    ),
    'api_v1_companies_list': _McpSpec(
        'List member companies',
        'Companies where the caller is a member.',
        'Read-only.',
    ),
    'api_v1_companies_retrieve': _McpSpec(
        'Read company settings',
        'Returns company name, owners, and join access settings.',
        'Read-only.',
    ),
    'api_v1_companies_update': _McpSpec(
        'Replace company settings',
        'Updates name, owners, join access, and desktop redirect settings.',
        'Updates company row.',
        read_only=False,
    ),
    'api_v1_companies_partial_update': _McpSpec(
        'Patch company settings',
        'Partial update of company settings.',
        'Updates company row.',
        read_only=False,
    ),
    'api_v1_invitations_list': _McpSpec(
        'List open invitations',
        'Pending and blocking revoked invitations for the company.',
        'Read-only.',
        sensitive=True,
    ),
    'api_v1_invitations_create': _McpSpec(
        'Invite a user by email',
        'Creates a pending invitation and sends email or webhook event.',
        'Inserts invitation row.',
        sends_email=True, sensitive=True, read_only=False,
    ),
    'api_v1_invitations_destroy': _McpSpec(
        'Delete an invitation row',
        'Hard-deletes an invitation record.',
        'Deletes invitation row.',
        destructive=True, sensitive=True, read_only=False,
    ),
    'api_v1_invitations_revoke': _McpSpec(
        'Revoke a pending invitation',
        'Marks invitation revoked so sign-in is blocked.',
        'Updates invitation status.',
        sensitive=True, read_only=False,
    ),
    'api_v1_events_list': _McpSpec(
        'List identity event log',
        'Paginated audit events for the company.',
        'Read-only.',
        sensitive=True,
    ),
    'api_v1_events_retrieve': _McpSpec(
        'Read one event log row',
        'Returns full event payload for one row.',
        'Read-only.',
        sensitive=True,
    ),
    'api_v1_events_types_list': _McpSpec(
        'List event log types',
        'Catalog types stored in the event log.',
        'Read-only.',
    ),
    'api_v1_events_retention_retrieve': _McpSpec(
        'Read event log retention',
        'Returns configured retention and stale flag.',
        'Read-only.',
    ),
    'api_v1_actions_events_list': _McpSpec(
        'List Actions event types',
        'Domain events available for webhook rules.',
        'Read-only.',
    ),
    'api_v1_actions_rules_list': _McpSpec(
        'List Actions webhook rules',
        'Signed HTTPS webhook rules for identity domain events.',
        'Read-only.',
    ),
    'api_v1_actions_rules_create': _McpSpec(
        'Create Actions webhook rule',
        'Creates a webhook rule and returns signing secret once.',
        'Inserts rule with encrypted secret.',
        sensitive=True, read_only=False,
    ),
    'api_v1_actions_rules_retrieve': _McpSpec(
        'Read one Actions webhook rule',
        'Returns rule metadata without plaintext secret.',
        'Read-only.',
    ),
    'api_v1_actions_rules_partial_update': _McpSpec(
        'Update Actions webhook rule',
        'Patches URL, enabled flag, or filters.',
        'Updates rule row.',
        read_only=False,
    ),
    'api_v1_actions_rules_destroy': _McpSpec(
        'Delete Actions webhook rule',
        'Deletes the webhook rule.',
        'Removes rule row.',
        destructive=True, read_only=False,
    ),
    'api_v1_actions_rules_rotate_secret': _McpSpec(
        'Rotate webhook signing secret',
        'Issues a new HMAC secret returned once.',
        'Updates encrypted secret.',
        sensitive=True, read_only=False,
    ),
    'api_v1_actions_rules_send_test': _McpSpec(
        'Send test webhook delivery',
        'Enqueues a synthetic event to the rule URL.',
        'Inserts outbox delivery row.',
        read_only=False,
    ),
    'api_v1_actions_deliveries_list': _McpSpec(
        'List webhook deliveries',
        'Recent webhook outbox rows for the company.',
        'Read-only.',
    ),
    'api_v1_actions_deliveries_retrieve': _McpSpec(
        'Read one webhook delivery',
        'Returns attempts and envelope payload.',
        'Read-only.',
    ),
    'api_v1_actions_deliveries_requeue': _McpSpec(
        'Requeue failed webhook delivery',
        'Resets a failed delivery to pending.',
        'Updates outbox status.',
        read_only=False,
    ),
    'api_v1_mcp_services_list': _McpSpec(
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
