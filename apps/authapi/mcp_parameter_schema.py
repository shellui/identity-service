"""Enums and descriptions on the OpenAPI document the AI gateway reads."""

from __future__ import annotations

from typing import Any

from apps.authapi.mcp_openapi import mcp_extension

ACCESS_VALUES = ['enabled', 'disabled', 'any']
ROLE_VALUES = ['owner', 'staff', 'member']
DELIVERY_STATUS_VALUES = ['pending', 'delivered', 'failed', 'dead']
LANGUAGE_VALUES = ['en', 'fr']
ACCESS_MODE_VALUES = ['public', 'domain', 'invite']
REDIRECT_SOURCE_VALUES = ['manual', 'hosting']
EVENT_SCOPE_VALUES = ['company', 'platform']

PATH_PARAM_DESCRIPTIONS: dict[str, dict[str, str]] = {
    'identity_get_users': {'id': 'Company user id.'},
    'identity_replace_users': {'id': 'Company user id.'},
    'identity_delete_users': {'id': 'Company user id.'},
    'identity_get_groups': {'id': 'Company group id.'},
    'identity_replace_groups': {'id': 'Company group id.'},
    'identity_update_groups': {'id': 'Company group id.'},
    'identity_delete_groups': {'id': 'Company group id.'},
    'identity_get_companies': {'id': 'Company id.'},
    'identity_replace_companies': {'id': 'Company id.'},
    'identity_update_companies': {'id': 'Company id.'},
    'identity_delete_invitations': {'id': 'Invitation id.'},
    'identity_revoke_invitations': {'id': 'Invitation id.'},
    'identity_get_oauth_clients': {'id': 'OAuth client mapping id.'},
    'identity_replace_oauth_clients': {'id': 'OAuth client mapping id.'},
    'identity_delete_oauth_clients': {'id': 'OAuth client mapping id.'},
    'identity_get_oauth_redirects': {'id': 'Redirect id.'},
    'identity_update_oauth_redirects': {'id': 'Redirect id.'},
    'identity_delete_oauth_redirects': {'id': 'Redirect id.'},
    'identity_replace_oauth_social_apps': {'id': 'SocialApp id.'},
    'identity_delete_oauth_social_apps': {'id': 'SocialApp id.'},
    'identity_get_action_rules': {'id': 'Webhook rule id.'},
    'identity_update_action_rules': {'id': 'Webhook rule id.'},
    'identity_delete_action_rules': {'id': 'Webhook rule id.'},
    'identity_rotate_rule_secret': {'id': 'Webhook rule id.'},
    'identity_send_test_rule': {'id': 'Webhook rule id.'},
    'identity_get_events': {'id': 'Event id.'},
    'identity_get_action_deliveries': {'delivery_id': 'Webhook delivery id.'},
    'identity_requeue_action_deliveries': {'delivery_id': 'Webhook delivery id.'},
    'identity_revoke_scim_tokens': {'token_id': 'SCIM token id.'},
    'identity_revoke_personal_access_tokens': {'key_id': 'Personal access token id.'},
}


def webhook_event_ids() -> list[str]:
    from apps.actions.registry import webhook_event_types

    return [event.id for event in webhook_event_types()]


def catalog_event_ids() -> list[str]:
    from django.conf import settings

    from apps.actions.registry import all_event_types

    role = getattr(settings, 'SHELLUI_INSTANCE_ROLE', '')
    ids = []
    for event in all_event_types():
        if event.id.startswith('identity.federation.') and role != 'global':
            continue
        ids.append(event.id)
    return ids


def provider_slugs() -> list[str]:
    from apps.authapi.provider_registry import supported_oauth_provider_slugs

    return sorted(supported_oauth_provider_slugs())


def _string_enum(values: list[str], description: str) -> dict[str, Any]:
    return {'type': 'string', 'enum': list(values), 'description': description}


def _array_enum(values: list[str], description: str) -> dict[str, Any]:
    return {
        'type': 'array',
        'description': description,
        'items': {'type': 'string', 'enum': list(values)},
    }


def _query_overrides(operation_id: str) -> dict[str, dict[str, Any]]:
    webhook_ids = webhook_event_ids()
    return {
        'identity_get_users_audience': {
            'access': _string_enum(ACCESS_VALUES, 'Membership filter. enabled is the default.'),
            'roles': _array_enum(ROLE_VALUES, 'Roles to match. One or more of owner, staff, or member.'),
        },
        'identity_list_action_deliveries': {
            'status': _string_enum(DELIVERY_STATUS_VALUES, 'Delivery status.'),
            'event_type': _string_enum(webhook_ids, 'Webhook event type id to filter on.'),
        },
        'identity_list_events': {
            'event_type': _array_enum(catalog_event_ids(), 'Event type ids to include. One or more.'),
            'scope': _string_enum(
                EVENT_SCOPE_VALUES,
                'Event scope. company is the default. platform is staff only and returns 403 for other callers.',
            ),
        },
        'identity_get_events': {
            'scope': _string_enum(
                EVENT_SCOPE_VALUES,
                'Event scope. company is the default. platform is staff only and returns 403 for other callers.',
            ),
        },
    }.get(operation_id, {})


def _body_overrides(operation_id: str) -> dict[str, dict[str, Any]]:
    webhook_ids = webhook_event_ids()
    slugs = provider_slugs()
    event_type = _string_enum(webhook_ids, 'Webhook event type id.')
    access_mode = _string_enum(ACCESS_MODE_VALUES, 'How people join the company: public, domain, or invite.')
    return {
        'identity_create_invitations': {
            'language': _string_enum(LANGUAGE_VALUES, 'Email language: en or fr.'),
        },
        'identity_create_action_rules': {'event_type': event_type},
        'identity_update_action_rules': {'event_type': event_type},
        'identity_create_oauth_social_apps': {
            'docs_slug': _string_enum(slugs, 'Catalog provider slug, for example github.'),
            'provider': _string_enum(slugs, 'Same catalog slugs as docs_slug. Send one of the two.'),
        },
        'identity_replace_companies': {'access_mode': access_mode},
        'identity_update_companies': {'access_mode': access_mode},
        'identity_create_oauth_redirects': {
            'source': _string_enum(REDIRECT_SOURCE_VALUES, 'Who created the redirect: manual or hosting.'),
        },
    }.get(operation_id, {})


def _components(result: dict[str, Any]) -> dict[str, Any]:
    return ((result.get('components') or {}).get('schemas')) or {}


def _iter_mcp_operations(result: dict[str, Any]):
    for path_item in (result.get('paths') or {}).values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if isinstance(operation, dict) and mcp_extension(operation) is not None:
                yield operation


def _ref_name(ref: str) -> str | None:
    if ref.startswith('#/components/schemas/'):
        return ref.rsplit('/', 1)[-1]
    return None


def _enum_from_node(
    node: Any,
    components: dict[str, Any],
    seen: frozenset[str],
) -> tuple[list[Any] | None, bool, str]:
    """Return enum values, whether null is allowed, and a description, for a pure enum node."""
    if not isinstance(node, dict):
        return None, False, ''
    description = str(node.get('description') or '')
    nullable = bool(node.get('nullable')) or node.get('type') == 'null'
    if isinstance(node.get('enum'), list):
        values: list[Any] = []
        for value in node['enum']:
            if value is None or value == '':
                nullable = True
                continue
            if value not in values:
                values.append(value)
        return (values or None), nullable, description
    ref = node.get('$ref')
    if isinstance(ref, str):
        name = _ref_name(ref)
        if not name or name in seen:
            return None, nullable, description
        values, ref_null, ref_description = _enum_from_node(components.get(name) or {}, components, seen | {name})
        return values, nullable or ref_null, description or ref_description
    for key in ('oneOf', 'anyOf', 'allOf'):
        variants = node.get(key)
        if not isinstance(variants, list) or not variants:
            continue
        values = []
        for variant in variants:
            if not isinstance(variant, dict):
                return None, nullable, description
            if variant.get('type') == 'null':
                nullable = True
                continue
            collected, var_null, var_description = _enum_from_node(variant, components, seen)
            if collected is None:
                return None, nullable, description
            nullable = nullable or var_null
            description = description or var_description
            for value in collected:
                if value not in values:
                    values.append(value)
        return (values or None), nullable, description
    return None, nullable, description


def _collapse_enum(node: dict[str, Any], components: dict[str, Any]) -> dict[str, Any] | None:
    values, nullable, description = _enum_from_node(node, components, frozenset())
    if not values:
        return None
    collapsed: dict[str, Any] = {'type': 'string', 'enum': values}
    if description and not description.lstrip().startswith('*'):
        collapsed['description'] = description
    if nullable:
        collapsed['nullable'] = True
    return collapsed


def _collapse_property_enums(props: dict[str, Any], components: dict[str, Any]) -> None:
    for key, node in list(props.items()):
        if not isinstance(node, dict):
            continue
        if node.get('type') == 'array' and isinstance(node.get('items'), dict):
            collapsed = _collapse_enum(node['items'], components)
            if collapsed:
                node['items'] = {k: v for k, v in collapsed.items() if k != 'nullable'}
            continue
        collapsed = _collapse_enum(node, components)
        if collapsed:
            props[key] = collapsed


def _collapse_schema_tree(result: dict[str, Any]) -> None:
    components = _components(result)
    for schema in components.values():
        if isinstance(schema, dict) and isinstance(schema.get('properties'), dict):
            _collapse_property_enums(schema['properties'], components)
    for operation in _iter_mcp_operations(result):
        for param in operation.get('parameters') or []:
            if not isinstance(param, dict):
                continue
            schema = param.get('schema')
            if isinstance(schema, dict):
                collapsed = _collapse_enum(schema, components)
                if collapsed:
                    param['schema'] = collapsed


def _body_properties(operation: dict[str, Any], components: dict[str, Any]) -> dict[str, Any] | None:
    body = operation.get('requestBody') or {}
    if not isinstance(body, dict):
        return None
    content = body.get('content') or {}
    if not isinstance(content, dict):
        return None
    schema = (content.get('application/json') or {}).get('schema') or {}
    if not isinstance(schema, dict):
        return None
    ref = schema.get('$ref')
    if isinstance(ref, str):
        name = _ref_name(ref)
        target = components.get(name) if name else None
        props = target.get('properties') if isinstance(target, dict) else None
        return props if isinstance(props, dict) else None
    props = schema.get('properties')
    return props if isinstance(props, dict) else None


def _apply_parameter_schema(operation: dict[str, Any], name: str, schema: dict[str, Any]) -> None:
    for param in operation.get('parameters') or []:
        if not isinstance(param, dict) or param.get('name') != name:
            continue
        if param.get('in') not in (None, 'query'):
            continue
        param['schema'] = schema
        param['description'] = schema.get('description') or param.get('description') or ''


def postprocess_mcp_parameter_schema(result: dict[str, Any]) -> dict[str, Any]:
    """Inline choice enums and attach fixed value sets the gateway can read."""
    _collapse_schema_tree(result)
    components = _components(result)
    for operation in _iter_mcp_operations(result):
        operation_id = str(operation.get('operationId') or '')
        parameters = [
            param
            for param in (operation.get('parameters') or [])
            if not (isinstance(param, dict) and param.get('name') == 'format' and param.get('in') == 'query')
        ]
        operation['parameters'] = parameters
        for param in parameters:
            if not isinstance(param, dict) or param.get('in') != 'path':
                continue
            description = PATH_PARAM_DESCRIPTIONS.get(operation_id, {}).get(str(param.get('name') or ''))
            if not description:
                continue
            param['description'] = description
            schema = param.get('schema')
            if isinstance(schema, dict):
                schema['description'] = description
        for name, schema in _query_overrides(operation_id).items():
            _apply_parameter_schema(operation, name, schema)
        props = _body_properties(operation, components)
        for name, schema in _body_overrides(operation_id).items():
            if props is not None and name in props:
                props[name] = schema
    return result
