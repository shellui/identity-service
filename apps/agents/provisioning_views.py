"""Provisioning hooks for global MCP agents (called by saas-service)."""

from __future__ import annotations

import json
import uuid

from rest_framework.response import Response

from apps.agents.global_revocation import revoke_regional_agents_for_global
from apps.federation.provisioning import ProvisioningError, _ProvisioningView


class ProvisioningGlobalAgentRevokeView(_ProvisioningView):
    def post(self, request):
        def work():
            try:
                body = json.loads(request.body.decode('utf-8') or '{}')
            except json.JSONDecodeError as exc:
                raise ProvisioningError(400, 'invalid_request', 'Body must be JSON.') from exc
            raw = body.get('global_agent_id')
            try:
                global_agent_id = uuid.UUID(str(raw))
            except (TypeError, ValueError) as exc:
                raise ProvisioningError(400, 'invalid_request', 'global_agent_id must be a UUID.') from exc
            count = revoke_regional_agents_for_global(global_agent_id)
            return Response({'global_agent_id': str(global_agent_id), 'revoked_count': count})

        return self._run(request, work, write=True)
