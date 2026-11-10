"""AutoSchema that refuses ``x-mcp`` on internal routes."""

from __future__ import annotations

from drf_spectacular.openapi import AutoSchema

from apps.authapi.mcp_openapi import MCP_EXCLUDED_PATH_PREFIXES


class McpAutoSchema(AutoSchema):
    def _get_request_for_media_type(self, serializer, direction='request'):
        # drf-spectacular marks every PATCH body partial. These views run the same
        # validation as PUT, so required fields must stay required in the MCP schema.
        if self.method == 'PATCH' and getattr(self.view, 'schema_patch_keeps_required', False):
            saved = self.method
            self.method = 'PUT'
            try:
                return super()._get_request_for_media_type(serializer, direction)
            finally:
                self.method = saved
        return super()._get_request_for_media_type(serializer, direction)

    def get_operation(self, path, path_regex, path_prefix, method, registry):
        operation = super().get_operation(path, path_regex, path_prefix, method, registry)
        if not operation:
            return operation
        if operation.get('x-mcp') and any(str(path).startswith(prefix) for prefix in MCP_EXCLUDED_PATH_PREFIXES):
            raise AssertionError(f'x-mcp is not allowed on excluded path: {path}')
        operation.pop('extensions', None)
        return operation
