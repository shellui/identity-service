"""AutoSchema that refuses ``x-mcp`` on internal routes."""

from __future__ import annotations

from rest_framework.fields import empty
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

    def _get_request_body(self, direction='request'):
        # drf-spectacular drops DELETE bodies. Hosting redirect removal takes
        # ``base_url`` in the body, and that field has to be in the published schema.
        if self.method == 'DELETE' and self._delete_declares_request_body():
            self.method = 'POST'
            try:
                return super()._get_request_body(direction)
            finally:
                self.method = 'DELETE'
        return super()._get_request_body(direction)

    def _delete_declares_request_body(self) -> bool:
        # ``extend_schema(request=...)`` closes over ``request``. Calling
        # ``get_request_serializer`` on a DELETE that did not declare one falls
        # through to serializer guessing and warns.
        method = getattr(type(self), 'get_request_serializer', None)
        func = getattr(method, '__func__', method)
        code = getattr(func, '__code__', None)
        closure = getattr(func, '__closure__', None)
        if code is None or closure is None or 'request' not in code.co_freevars:
            return False
        request = closure[code.co_freevars.index('request')].cell_contents
        return request is not empty and request is not None

    def get_operation(self, path, path_regex, path_prefix, method, registry):
        operation = super().get_operation(path, path_regex, path_prefix, method, registry)
        if not operation:
            return operation
        if operation.get('x-mcp') and any(str(path).startswith(prefix) for prefix in MCP_EXCLUDED_PATH_PREFIXES):
            raise AssertionError(f'x-mcp is not allowed on excluded path: {path}')
        operation.pop('extensions', None)
        return operation
