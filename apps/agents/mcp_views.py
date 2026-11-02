"""Identity-service /mcp Streamable HTTP endpoint."""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.generators import SchemaGenerator
from rest_framework.request import Request
from shellui_django.mcp.resources import access_token_audience_matches, mcp_resource_from_origin
from shellui_django.mcp.server import McpServer

from apps.agents.approval_internal import (
    approval_binding_from_claims,
    lookup_approval_row,
    public_approval_status,
)
from apps.agents.models import Agent, McpApprovalRequest
from apps.agents.revocation import blocked_agent_ids
from apps.authapi.authentication import ShellUIJWTAuthentication
from shellui_django.mcp.masking import redact_mapping

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
            identity_revocation_check=lambda agent_id, company_id: agent_id
            in set(blocked_agent_ids(company_id=company_id)),
            on_call=_record_local_call,
            approval_handler=_maybe_create_approval,
            approval_state=_approval_state,
            approval_consume=_consume_approval,
        )
    return _server


def _record_local_call(entry: dict) -> None:
    from apps.agents.models import McpCallLog

    agent_id = entry.get('agent_id')
    company_id = entry.get('company_id')
    if not agent_id or company_id is None:
        return
    try:
        agent = Agent.objects.get(pk=agent_id, company_id=company_id)
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


def _approval_binding_from_payload(payload: dict) -> dict | None:
    return approval_binding_from_claims(
        {
            'agent_id': payload.get('agent_id'),
            'company_id': payload.get('company_id'),
            'service': payload.get('service'),
            'action': payload.get('action'),
            'arguments_hash': payload.get('arguments_hash'),
        }
    )


def _approval_state(payload: dict) -> str | None:
    binding = _approval_binding_from_payload(payload)
    if binding is None:
        return None
    row = lookup_approval_row(binding)
    if row is None:
        return None
    now = timezone.now()
    public_status = public_approval_status(row, now=now)
    if public_status == 'expired' and row.status == McpApprovalRequest.STATUS_EXECUTED:
        return 'executed'
    if public_status == 'approved':
        payload['approval_id'] = str(row.id)
        return 'approved'
    if public_status == 'pending':
        return 'pending'
    if public_status == 'denied':
        return None
    return None


def _consume_approval(approval_id: str, payload: dict | None = None) -> bool:
    payload = payload or {}
    binding = _approval_binding_from_payload(payload)
    if binding is None:
        return False
    now = timezone.now()
    with transaction.atomic():
        try:
            row = McpApprovalRequest.objects.select_for_update().get(
                pk=approval_id,
                agent_id=binding['agent_id'],
                company_id=binding['company_id'],
                service=binding['service'],
                arguments_hash=binding['arguments_hash'],
            )
        except McpApprovalRequest.DoesNotExist:
            return False
        if row.status != McpApprovalRequest.STATUS_APPROVED or row.expires_at <= now:
            return False
        row.status = McpApprovalRequest.STATUS_EXECUTED
        row.executed_at = now
        row.save(update_fields=['status', 'executed_at'])
    return True


def _maybe_create_approval(payload: dict) -> dict | None:
    agent_id = payload.get('agent_id')
    company_id = payload.get('company_id')
    if not agent_id or company_id is None:
        return None
    try:
        agent = Agent.objects.get(pk=agent_id, company_id=company_id)
    except Agent.DoesNotExist:
        return None

    method = str(payload.get('method') or '').strip().upper()
    path = str(payload.get('path') or '').strip()
    if method and path:
        target = f'{method} {path}'[:500]
    else:
        target = path[:500]
    row = McpApprovalRequest.objects.create(
        agent=agent,
        company_id=company_id,
        service=str(payload.get('service') or ''),
        action=str(payload.get('action') or ''),
        target=target,
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
    expected = mcp_resource_from_origin(getattr(settings, 'JWT_ISSUER', '') or '')
    claims = dict(token.payload)
    if not access_token_audience_matches(claims, expected):
        return None
    request.user = _user
    return claims


@csrf_exempt
def mcp_endpoint(request: HttpRequest):
    claims = _agent_claims(request)
    return _get_server().handle(request, agent_claims=claims)
