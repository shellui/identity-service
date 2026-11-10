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
        'Lists users in the company, with optional q search and page or page_size. Returns a page of profiles.',
        'Lists users in the company, with optional q search and page or page_size. Returns a page of profiles.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_get_users': _McpSpec(
        'Reads company user id. Returns the profile, membership, and groups.',
        'Reads company user id. Returns the profile, membership, and groups.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_replace_users': _McpSpec(
        'Updates company user id: name, enabled state, manual groups, or metadata. Returns the updated user.',
        'Updates company user id: name, enabled state, manual groups, or metadata. Returns the updated user.',
        'May update user, membership, and group rows.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_delete_users': _McpSpec(
        'Removes user id from the company and deletes the account when it was their last company. Returns an empty success response.',
        'Removes user id from the company and deletes the account when it was their last company. Returns an empty success response.',
        'Deletes membership or user rows.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_get_users_audience': _McpSpec(
        'Counts or lists company users matching roles, access, group_ids, and date filters, without sending email. Returns count and, unless count_only is true, a page of matches.',
        'Counts or lists company users matching roles, access, group_ids, and date filters, without sending email. Returns count and, unless count_only is true, a page of matches.',
        'Read-only evaluation.',
        sensitive=True,
    ),
    'identity_list_groups': _McpSpec(
        'Lists manual and SCIM groups in the company. Returns each group and its member count.',
        'Lists manual and SCIM groups in the company. Returns each group and its member count.',
        'Read-only.',
    ),
    'identity_create_groups': _McpSpec(
        'Creates an empty manual group named display_name. Returns the new group.',
        'Creates an empty manual group named display_name. Returns the new group.',
        'Inserts a group row.',
        read_only=False,
    ),
    'identity_get_groups': _McpSpec(
        'Reads company group id. Returns its metadata and member count.',
        'Reads company group id. Returns its metadata and member count.',
        'Read-only.',
    ),
    'identity_replace_groups': _McpSpec(
        'Replaces the display name of manual group id. Returns the updated group.',
        'Replaces the display name of manual group id. Returns the updated group.',
        'Updates the group row.',
        read_only=False,
    ),
    'identity_update_groups': _McpSpec(
        'Updates the display name of manual group id. Returns the updated group.',
        'Updates the display name of manual group id. Returns the updated group.',
        'Updates the group row.',
        read_only=False,
    ),
    'identity_delete_groups': _McpSpec(
        'Deletes manual group id and refuses SCIM-managed groups. Returns an empty success response.',
        'Deletes manual group id and refuses SCIM-managed groups. Returns an empty success response.',
        'Removes the group row.',
        destructive=True,
        read_only=False,
    ),
    'identity_list_oauth_clients': _McpSpec(
        'Lists the company OAuth client mappings. Returns provider, SocialApp id, and whether each mapping is active.',
        'Lists the company OAuth client mappings. Returns provider, SocialApp id, and whether each mapping is active.',
        'Read-only.',
    ),
    'identity_create_oauth_clients': _McpSpec(
        'Links SocialApp social_app_id to the company as an OAuth client. Returns the new mapping.',
        'Links SocialApp social_app_id to the company as an OAuth client. Returns the new mapping.',
        'Inserts a mapping row.',
        destructive=True,
        read_only=False,
    ),
    'identity_get_oauth_clients': _McpSpec(
        'Reads OAuth client mapping id. Returns the provider, SocialApp id, and active flag.',
        'Reads OAuth client mapping id. Returns the provider, SocialApp id, and active flag.',
        'Read-only.',
    ),
    'identity_replace_oauth_clients': _McpSpec(
        'Updates OAuth client mapping id, including is_active or social_app_id. Returns the updated mapping.',
        'Updates OAuth client mapping id, including is_active or social_app_id. Returns the updated mapping.',
        'Updates mapping row.',
        destructive=True,
        read_only=False,
    ),
    'identity_delete_oauth_clients': _McpSpec(
        'Deletes OAuth client mapping id and leaves the SocialApp in place. Returns an empty success response.',
        'Deletes OAuth client mapping id and leaves the SocialApp in place. Returns an empty success response.',
        'Deletes mapping row.',
        destructive=True,
        read_only=False,
    ),
    'identity_list_oauth_redirects': _McpSpec(
        'Lists redirect URIs allowed for this company. Returns each allowlist row.',
        'Lists redirect URIs allowed for this company. Returns each allowlist row.',
        'Read-only.',
    ),
    'identity_create_oauth_redirects': _McpSpec(
        'Adds base_url to the company redirect allowlist (source is manual or hosting) and returns the new redirect.',
        'Adds base_url to the company redirect allowlist (source is manual or hosting) and returns the new redirect.',
        'Inserts redirect row.',
        destructive=True,
        read_only=False,
    ),
    'identity_get_oauth_redirects': _McpSpec(
        'Reads redirect id. Returns that allowlist row.',
        'Reads redirect id. Returns that allowlist row.',
        'Read-only.',
    ),
    'identity_update_oauth_redirects': _McpSpec(
        'Updates redirect id: base_url, label, or is_active. Returns the updated row.',
        'Updates redirect id: base_url, label, or is_active. Returns the updated row.',
        'Updates redirect row.',
        destructive=True,
        read_only=False,
    ),
    'identity_delete_oauth_redirects': _McpSpec(
        'Removes redirect id from the allowlist. Returns an empty success response.',
        'Removes redirect id from the allowlist. Returns an empty success response.',
        'Deletes redirect row.',
        destructive=True,
        read_only=False,
    ),
    'identity_list_oauth_social_apps': _McpSpec(
        'Lists OAuth SocialApp keys owned by the company. Returns client ids and providers, not client secrets.',
        'Lists OAuth SocialApp keys owned by the company. Returns client ids and providers, not client secrets.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_create_oauth_social_apps': _McpSpec(
        'Creates an OAuth SocialApp for docs_slug (or provider) with client_id and client_secret, and returns the new key. The client secret is shown once on the admin HTTP response and is masked in this result.',
        'Creates an OAuth SocialApp for docs_slug (or provider) with client_id and client_secret, and returns the new key. The client secret is shown once on the admin HTTP response and is masked in this result.',
        'Inserts SocialApp row with encrypted secret.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_replace_oauth_social_apps': _McpSpec(
        'Updates SocialApp id (client_id, client_secret, tenant, or extra_settings) and returns the updated key. A new client secret is masked in this result.',
        'Updates SocialApp id (client_id, client_secret, tenant, or extra_settings) and returns the updated key. A new client secret is masked in this result.',
        'Persists SocialApp fields.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_delete_oauth_social_apps': _McpSpec(
        'Deletes SocialApp id when no other company maps it and removing it would not lock out sign-in. Returns an empty success response.',
        'Deletes SocialApp id when no other company maps it and removing it would not lock out sign-in. Returns an empty success response.',
        'Removes SocialApp row.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_get_oauth_provider_catalog': _McpSpec(
        'Reads the Shellui OAuth provider catalog, including callback URLs and setup fields, and returns it. Pass include_legacy to include replaced providers.',
        'Reads the Shellui OAuth provider catalog, including callback URLs and setup fields, and returns it. Pass include_legacy to include replaced providers.',
        'Read-only.',
    ),
    'identity_replace_hosting_oauth_redirects': _McpSpec(
        'Replaces hosting-managed redirect URIs with base_url. Returns the synced redirect.',
        'Replaces hosting-managed redirect URIs with base_url. Returns the synced redirect.',
        'Updates redirect rows.',
        destructive=True,
        read_only=False,
    ),
    'identity_delete_hosting_oauth_redirects': _McpSpec(
        'Deletes the hosting-managed redirect for base_url. Returns an empty success response.',
        'Deletes the hosting-managed redirect for base_url. Returns an empty success response.',
        'Deletes redirect rows.',
        destructive=True,
        read_only=False,
    ),
    'identity_get_auth_methods': _McpSpec(
        'Reads which sign-in methods are enabled, including magic link, OAuth, and SAML. Returns the company auth settings.',
        'Reads which sign-in methods are enabled, including magic link, OAuth, and SAML. Returns the company auth settings.',
        'Read-only.',
    ),
    'identity_update_auth_methods': _McpSpec(
        'Updates enable_magic_link for the company. Returns the auth settings.',
        'Updates enable_magic_link for the company. Returns the auth settings.',
        'Updates company auth settings.',
        destructive=True,
        read_only=False,
    ),
    'identity_replace_auth_methods': _McpSpec(
        'Replaces company auth settings, including enable_magic_link. Returns the auth settings.',
        'Replaces company auth settings, including enable_magic_link. Returns the auth settings.',
        'Updates company auth settings.',
        destructive=True,
        read_only=False,
    ),
    'identity_get_scim_status': _McpSpec(
        'Reads whether SCIM provisioning is enabled and which base URL to use. Returns the SCIM status.',
        'Reads whether SCIM provisioning is enabled and which base URL to use. Returns the SCIM status.',
        'Read-only.',
    ),
    'identity_list_scim_tokens': _McpSpec(
        'Lists SCIM bearer tokens for the company. Returns token metadata, not the bearer secret.',
        'Lists SCIM bearer tokens for the company. Returns token metadata, not the bearer secret.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_create_scim_tokens': _McpSpec(
        'Creates a SCIM bearer token with optional name and returns its metadata. The secret is shown once on the admin HTTP response and is masked in this result.',
        'Creates a SCIM bearer token with optional name and returns its metadata. The secret is shown once on the admin HTTP response and is masked in this result.',
        'Inserts SCIM token row.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_revoke_scim_tokens': _McpSpec(
        'Revokes the SCIM bearer token identified by token_id. Returns the revoked token.',
        'Revokes the SCIM bearer token identified by token_id. Returns the revoked token.',
        'Updates token revoked timestamp.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_list_personal_access_tokens': _McpSpec(
        'Lists personal access tokens for the caller in this company. Returns token metadata, not the token itself.',
        'Lists personal access tokens for the caller in this company. Returns token metadata, not the token itself.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_create_personal_access_tokens': _McpSpec(
        'Creates a personal access token with optional name, read_only, and access_global_metrics, and returns its metadata. The token is shown once on the admin HTTP response and is masked in this result.',
        'Creates a personal access token with optional name, read_only, and access_global_metrics, and returns its metadata. The token is shown once on the admin HTTP response and is masked in this result.',
        'Inserts PAT row.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_revoke_personal_access_tokens': _McpSpec(
        'Revokes the personal access token identified by key_id. Returns the revoked token.',
        'Revokes the personal access token identified by key_id. Returns the revoked token.',
        'Updates PAT revoked timestamp.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_list_companies': _McpSpec(
        'Lists companies where the caller is a member. Returns each company id and name.',
        'Lists companies where the caller is a member. Returns each company id and name.',
        'Read-only.',
    ),
    'identity_get_companies': _McpSpec(
        'Reads company id, including name, owners, and join access. Returns the company settings.',
        'Reads company id, including name, owners, and join access. Returns the company settings.',
        'Read-only.',
    ),
    'identity_replace_companies': _McpSpec(
        'Replaces company id settings such as name, owner_ids, access_mode, and desktop redirect schemes. Returns the updated company.',
        'Replaces company id settings such as name, owner_ids, access_mode, and desktop redirect schemes. Returns the updated company.',
        'Updates company row.',
        destructive=True,
        read_only=False,
    ),
    'identity_update_companies': _McpSpec(
        'Updates company id settings such as name, owner_ids, access_mode, and desktop redirect schemes. Returns the updated company.',
        'Updates company id settings such as name, owner_ids, access_mode, and desktop redirect schemes. Returns the updated company.',
        'Updates company row.',
        destructive=True,
        read_only=False,
    ),
    'identity_list_invitations': _McpSpec(
        'Lists pending invitations and revoked invitations that still block sign-in. Returns each invitation.',
        'Lists pending invitations and revoked invitations that still block sign-in. Returns each invitation.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_create_invitations': _McpSpec(
        'Invites email to the company, sends the invitation email, and returns the invitation. language is en or fr, and optional app_url is the link in that email.',
        'Invites email to the company, sends the invitation email, and returns the invitation. language is en or fr, and optional app_url is the link in that email.',
        'Inserts invitation row.',
        sends_email=True,
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_delete_invitations': _McpSpec(
        'Deletes revoked invitation id. Pending invitations must be revoked first, and a successful delete returns an empty response.',
        'Deletes revoked invitation id. Pending invitations must be revoked first, and a successful delete returns an empty response.',
        'Deletes invitation row.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_revoke_invitations': _McpSpec(
        'Revokes pending invitation id so it cannot be accepted. Returns the revoked invitation.',
        'Revokes pending invitation id so it cannot be accepted. Returns the revoked invitation.',
        'Updates invitation status.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_list_events': _McpSpec(
        'Lists identity audit events for the company. Filter with event_type, user_id, user, scope, or a created date range, and the result is a page of events.',
        'Lists identity audit events for the company. Filter with event_type, user_id, user, scope, or a created date range, and the result is a page of events.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_get_events': _McpSpec(
        'Reads event id. scope is company or platform (platform is staff only) and the result is the event payload.',
        'Reads event id. scope is company or platform (platform is staff only) and the result is the event payload.',
        'Read-only.',
        sensitive=True,
    ),
    'identity_list_events_types': _McpSpec(
        'Lists identity event types stored in the company event log. Returns each type id, label, and whether it can trigger a webhook.',
        'Lists identity event types stored in the company event log. Returns each type id, label, and whether it can trigger a webhook.',
        'Read-only.',
    ),
    'identity_get_events_retention': _McpSpec(
        'Reads how long identity events are kept and whether retention is stale. Returns the retention settings.',
        'Reads how long identity events are kept and whether retention is stale. Returns the retention settings.',
        'Read-only.',
    ),
    'identity_list_action_events': _McpSpec(
        'Lists identity events that can trigger an Actions webhook. Returns each event type and its payload fields.',
        'Lists identity events that can trigger an Actions webhook. Returns each event type and its payload fields.',
        'Read-only.',
    ),
    'identity_list_action_rules': _McpSpec(
        'Lists Actions webhook rules for the company. Returns each rule without its signing secret.',
        'Lists Actions webhook rules for the company. Returns each rule without its signing secret.',
        'Read-only.',
    ),
    'identity_create_action_rules': _McpSpec(
        'Creates a webhook rule for event_type that posts to url, and returns the rule. The signing secret is shown once on the admin HTTP response and is masked in this result.',
        'Creates a webhook rule for event_type that posts to url, and returns the rule. The signing secret is shown once on the admin HTTP response and is masked in this result.',
        'Inserts rule with encrypted secret. Nothing is sent until an event fires.',
        sensitive=True,
        read_only=False,
    ),
    'identity_get_action_rules': _McpSpec(
        'Reads webhook rule id. Returns the rule metadata without the signing secret.',
        'Reads webhook rule id. Returns the rule metadata without the signing secret.',
        'Read-only.',
    ),
    'identity_update_action_rules': _McpSpec(
        'Updates webhook rule id, including url, enabled, event_type, or the request headers. Returns the updated rule.',
        'Updates webhook rule id, including url, enabled, event_type, or the request headers. Returns the updated rule.',
        'Updates rule row. Nothing is sent until an event fires.',
        read_only=False,
    ),
    'identity_delete_action_rules': _McpSpec(
        'Deletes webhook rule id. Returns an empty success response.',
        'Deletes webhook rule id. Returns an empty success response.',
        'Removes rule row.',
        destructive=True,
        read_only=False,
    ),
    'identity_rotate_rule_secret': _McpSpec(
        'Rotates the signing secret for webhook rule id and returns the rule. The new secret is shown once on the admin HTTP response and is masked in this result.',
        'Rotates the signing secret for webhook rule id and returns the rule. The new secret is shown once on the admin HTTP response and is masked in this result.',
        'Updates encrypted secret.',
        destructive=True,
        sensitive=True,
        read_only=False,
    ),
    'identity_send_test_rule': _McpSpec(
        'Sends a synthetic webhook for rule id to its URL. Returns the delivery result.',
        'Sends a synthetic webhook for rule id to its URL. Returns the delivery result.',
        'Inserts outbox delivery row.',
        destructive=True,
        read_only=False,
    ),
    'identity_list_action_deliveries': _McpSpec(
        'Lists webhook deliveries. Filter with status, event_type, action_rule_id, or a created date range, and the result is a page of deliveries.',
        'Lists webhook deliveries. Filter with status, event_type, action_rule_id, or a created date range, and the result is a page of deliveries.',
        'Read-only.',
    ),
    'identity_get_action_deliveries': _McpSpec(
        'Reads the webhook delivery identified by delivery_id, including attempts and the event envelope. Returns that delivery.',
        'Reads the webhook delivery identified by delivery_id, including attempts and the event envelope. Returns that delivery.',
        'Read-only.',
    ),
    'identity_requeue_action_deliveries': _McpSpec(
        'Queues failed delivery delivery_id again so it is sent to the rule URL. Returns the updated delivery.',
        'Queues failed delivery delivery_id again so it is sent to the rule URL. Returns the updated delivery.',
        'Updates outbox status.',
        destructive=True,
        read_only=False,
    ),
    'identity_list_services': _McpSpec(
        'Lists Shellui service MCP endpoints connected for this company. Returns each service id and URL.',
        'Lists Shellui service MCP endpoints connected for this company. Returns each service id and URL.',
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
