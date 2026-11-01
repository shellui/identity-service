"""Identity-service /mcp Streamable HTTP endpoint."""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.generators import SchemaGenerator
from rest_framework.request import Request
from shellui_mcp.server import McpServer

from apps.agents.models import Agent, McpApprovalRequest
from apps.agents.revocation import blocked_agent_ids
from apps.authapi.authentication import ShellUIJWTAuthentication
from shellui_mcp.masking import redact_mapping

_server: McpServer | None = None


def _schema() -> dict:
    generator = SchemaGenerator()
    return generator.get_schema(request=None, public=True)


def _get_server() -> McpServer:
    global _server
    if _server is None:
        _server = McpServer(
            schema_provider=_schema,
            urlconf=settings.ROOT_URLCONF,
            service_name='identity',
            identity_revocation_check=lambda agent_id: agent_id in set(blocked_agent_ids()),
            on_call=_record_local_call,
            approval_handler=_maybe_create_approval,
        )
    return _server


def _record_local_call(entry: dict) -> None:
    from apps.agents.models import McpCallLog

    agent_id = entry.get('agent_id')
    company_id = entry.get('company_id')
    if not agent_id or company_id is None:
        return
    try:
        agent = Agent.objects.get(pk=agent_id)
    except Agent.DoesNotExist:
        return
    McpCallLog.objects.create(
        agent=agent,
        company_id=company_id,
        service=entry.get('service') or 'identity',
        tool=entry.get('tool') or '',
        http_method=entry.get('method') or '',
        path=entry.get('path') or '',
        status_code=int(entry.get('status') or 0),
        arguments_redacted=entry.get('arguments') or {},
    )


def _maybe_create_approval(payload: dict) -> dict | None:
    agent_id = payload.get('agent_id')
    company_id = payload.get('company_id')
    if not agent_id or company_id is None:
        return None
    try:
        agent = Agent.objects.get(pk=agent_id, company_id=company_id)
    except Agent.DoesNotExist:
        return None
    from django.utils import timezone

    row = McpApprovalRequest.objects.create(
        agent=agent,
        company_id=company_id,
        service=str(payload.get('service') or ''),
        action=str(payload.get('action') or ''),
        arguments_hash=str(payload.get('arguments_hash') or ''),
        arguments_redacted=redact_mapping(payload.get('arguments') or {}, read_sensitive=False),
        expires_at=timezone.now() + timedelta(minutes=10),
    )
    return {'id': str(row.id)}


def _agent_claims(request: HttpRequest) -> dict | None:
    auth = ShellUIJWTAuthentication()
    drf_request = Request(request)
    try:
        result = auth.authenticate(drf_request)
    except Exception:
        return None
    if not result:
        return None
    _user, token = result
    if not token.get('agent_id'):
        return None
    request.user = _user
    return dict(token)


@csrf_exempt
def mcp_endpoint(request: HttpRequest):
    claims = _agent_claims(request)
    return _get_server().handle(request, agent_claims=claims)
