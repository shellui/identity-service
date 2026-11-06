"""OpenAPI schema generation must describe every APIView without spectacular warnings."""

from __future__ import annotations

import tempfile

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase

from apps.authapi.mcp_openapi import (
    MCP_EXCLUDED_PATH_PREFIXES,
    MCP_EXPLICIT_REGISTRY,
    MCP_REQUIRED_OPERATION_IDS,
    MCP_REQUIRED_SECRET_SCHEMA_PROPERTIES,
    validate_mcp_schema,
    validate_mcp_secret_fields,
)


class OpenApiSchemaTests(SimpleTestCase):
    def test_spectacular_validate_fail_on_warn(self):
        with tempfile.NamedTemporaryFile(suffix='.yml') as handle:
            try:
                call_command(
                    'spectacular',
                    validate=True,
                    fail_on_warn=True,
                    file=handle.name,
                    stdout=handle,
                )
            except CommandError as exc:
                self.fail(str(exc))

        from drf_spectacular.generators import SchemaGenerator

        schema = SchemaGenerator().get_schema(request=None, public=True)
        paths = schema['paths']
        for path in (
            '/api/v1/users',
            '/api/v1/users/{id}',
            '/api/v1/groups',
            '/api/v1/oauth-clients',
            '/api/v1/actions/rules',
            '/api/v1/events',
            '/api/v1/mcp/services',
        ):
            self.assertIn(path, paths)

        operation_ids = [
            operation['operationId']
            for path_item in paths.values()
            for operation in path_item.values()
            if isinstance(operation, dict) and 'operationId' in operation
        ]
        self.assertEqual(len(operation_ids), len(set(operation_ids)), operation_ids)
        self.assertIn('api_v1_mcp_services_list', operation_ids)
        validate_mcp_schema(schema)
        validate_mcp_secret_fields(schema)

        for prefix in MCP_EXCLUDED_PATH_PREFIXES:
            for path in paths:
                self.assertFalse(path.startswith(prefix), path)

    def test_mcp_registry_matches_required_allowlist(self):
        self.assertEqual(set(MCP_EXPLICIT_REGISTRY), MCP_REQUIRED_OPERATION_IDS)

    def test_mcp_operations_are_fully_documented(self):
        from drf_spectacular.generators import SchemaGenerator

        schema = SchemaGenerator().get_schema(request=None, public=True)
        paths = schema['paths']
        required_errors = {400, 401, 403, 404, 409, 429}
        for op_id in MCP_REQUIRED_OPERATION_IDS:
            operation = None
            for path_item in paths.values():
                for op in path_item.values():
                    if isinstance(op, dict) and op.get('operationId') == op_id:
                        operation = op
                        break
            self.assertIsNotNone(operation, op_id)
            assert operation is not None
            self.assertTrue(operation.get('summary'), op_id)
            self.assertTrue(operation.get('description'), op_id)
            response_codes = {int(code) for code in operation.get('responses', {}) if str(code).isdigit()}
            self.assertTrue(required_errors <= response_codes, (op_id, response_codes))
            description = operation['description']
            for needle in ('Side effects:', 'Sends email:', 'Destructive:', 'Permissions:'):
                self.assertIn(needle, description, op_id)

    def test_required_secret_fields_list_is_documented(self):
        expected = sorted(f'{c}.{p}' for c, p in MCP_REQUIRED_SECRET_SCHEMA_PROPERTIES)
        self.assertEqual(
            expected,
            sorted(
                [
                    'ActionRuleCreate.secret',
                    'ShellUIAdminOAuthSocialAppCreate.client_secret',
                    'ShellUIAdminOAuthSocialAppUpdate.client_secret',
                ]
            ),
        )

    def test_validate_mcp_schema_rejects_forbidden_tags(self):
        schema = {
            'paths': {
                '/api/v1/metrics/all': {
                    'get': {
                        'operationId': 'api_v1_metrics_all_retrieve',
                        'x-mcp': {'read_only': True},
                    }
                }
            }
        }
        with self.assertRaises(AssertionError):
            validate_mcp_schema(schema)
