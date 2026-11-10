# Rewrite stored identity MCP tool names from api_v1_* operation ids.

from django.db import migrations

LEGACY_TOOL_NAMES = {
    'api_v1_actions_deliveries_list': 'identity_list_action_deliveries',
    'api_v1_actions_deliveries_requeue': 'identity_requeue_action_deliveries',
    'api_v1_actions_deliveries_retrieve': 'identity_get_action_deliveries',
    'api_v1_actions_events_list': 'identity_list_action_events',
    'api_v1_actions_rules_create': 'identity_create_action_rules',
    'api_v1_actions_rules_destroy': 'identity_delete_action_rules',
    'api_v1_actions_rules_list': 'identity_list_action_rules',
    'api_v1_actions_rules_partial_update': 'identity_update_action_rules',
    'api_v1_actions_rules_retrieve': 'identity_get_action_rules',
    'api_v1_actions_rules_rotate_secret': 'identity_rotate_rule_secret',
    'api_v1_actions_rules_send_test': 'identity_send_test_rule',
    'api_v1_auth_methods_partial_update': 'identity_update_auth_methods',
    'api_v1_auth_methods_retrieve': 'identity_get_auth_methods',
    'api_v1_auth_methods_update': 'identity_replace_auth_methods',
    'api_v1_companies_list': 'identity_list_companies',
    'api_v1_companies_partial_update': 'identity_update_companies',
    'api_v1_companies_retrieve': 'identity_get_companies',
    'api_v1_companies_update': 'identity_replace_companies',
    'api_v1_events_list': 'identity_list_events',
    'api_v1_events_retention_retrieve': 'identity_get_events_retention',
    'api_v1_events_retrieve': 'identity_get_events',
    'api_v1_events_types_list': 'identity_list_events_types',
    'api_v1_groups_create': 'identity_create_groups',
    'api_v1_groups_destroy': 'identity_delete_groups',
    'api_v1_groups_list': 'identity_list_groups',
    'api_v1_groups_partial_update': 'identity_update_groups',
    'api_v1_groups_retrieve': 'identity_get_groups',
    'api_v1_groups_update': 'identity_replace_groups',
    'api_v1_hosting_oauth_redirects_destroy': 'identity_delete_hosting_oauth_redirects',
    'api_v1_hosting_oauth_redirects_update': 'identity_replace_hosting_oauth_redirects',
    'api_v1_invitations_create': 'identity_create_invitations',
    'api_v1_invitations_destroy': 'identity_delete_invitations',
    'api_v1_invitations_list': 'identity_list_invitations',
    'api_v1_invitations_revoke': 'identity_revoke_invitations',
    'api_v1_mcp_services_list': 'identity_list_services',
    'api_v1_oauth_clients_create': 'identity_create_oauth_clients',
    'api_v1_oauth_clients_destroy': 'identity_delete_oauth_clients',
    'api_v1_oauth_clients_list': 'identity_list_oauth_clients',
    'api_v1_oauth_clients_retrieve': 'identity_get_oauth_clients',
    'api_v1_oauth_clients_update': 'identity_replace_oauth_clients',
    'api_v1_oauth_provider_catalog_retrieve': 'identity_get_oauth_provider_catalog',
    'api_v1_oauth_redirects_create': 'identity_create_oauth_redirects',
    'api_v1_oauth_redirects_destroy': 'identity_delete_oauth_redirects',
    'api_v1_oauth_redirects_list': 'identity_list_oauth_redirects',
    'api_v1_oauth_redirects_partial_update': 'identity_update_oauth_redirects',
    'api_v1_oauth_redirects_retrieve': 'identity_get_oauth_redirects',
    'api_v1_oauth_social_apps_create': 'identity_create_oauth_social_apps',
    'api_v1_oauth_social_apps_destroy': 'identity_delete_oauth_social_apps',
    'api_v1_oauth_social_apps_list': 'identity_list_oauth_social_apps',
    'api_v1_oauth_social_apps_update': 'identity_replace_oauth_social_apps',
    'api_v1_personal_access_tokens_create': 'identity_create_personal_access_tokens',
    'api_v1_personal_access_tokens_list': 'identity_list_personal_access_tokens',
    'api_v1_personal_access_tokens_revoke': 'identity_revoke_personal_access_tokens',
    'api_v1_scim_status': 'identity_get_scim_status',
    'api_v1_scim_tokens_create': 'identity_create_scim_tokens',
    'api_v1_scim_tokens_list': 'identity_list_scim_tokens',
    'api_v1_scim_tokens_revoke': 'identity_revoke_scim_tokens',
    'api_v1_users_audience': 'identity_get_users_audience',
    'api_v1_users_destroy': 'identity_delete_users',
    'api_v1_users_list': 'identity_list_users',
    'api_v1_users_retrieve': 'identity_get_users',
    'api_v1_users_update': 'identity_replace_users',
}


def rename_identity_tool_names(apps, schema_editor):
    McpCallLog = apps.get_model('agents', 'McpCallLog')
    McpApprovalRequest = apps.get_model('agents', 'McpApprovalRequest')
    McpApprovalSessionGrant = apps.get_model('agents', 'McpApprovalSessionGrant')
    for old, new in LEGACY_TOOL_NAMES.items():
        McpCallLog.objects.filter(tool=old).update(tool=new)
        McpCallLog.objects.filter(operation_title=old).update(operation_title=new)
        McpCallLog.objects.filter(resource_label=old).update(resource_label=new)
        McpApprovalRequest.objects.filter(action=old).update(action=new)
        McpApprovalSessionGrant.objects.filter(action=old).update(action=new)


class Migration(migrations.Migration):
    dependencies = [
        ('agents', '0024_mcp_device_authorization'),
    ]

    operations = [
        migrations.RunPython(rename_identity_tool_names, migrations.RunPython.noop),
    ]

