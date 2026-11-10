"""Identity-service /mcp Streamable HTTP endpoint."""

from __future__ import annotations

import contextvars
import json
import time
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.generators import SchemaGenerator
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
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

_mcp_tool_call_started_at: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    'identity_mcp_tool_call_started_at',
    default=None,
)
# First ``redact_mapping`` call inside a tools/call is the tool result. Later calls redact logs.
_mcp_result_redaction: contextvars.ContextVar[bool] = contextvars.ContextVar(
    'identity_mcp_result_redaction',
    default=False,
)

# One-time disclosures and non-secret metadata the name heuristic would hide.
# Schema ``x-mcp-secret`` markers still win. User-supplied blobs are not restored.
_DISCLOSED_RESULT_KEYS = frozenset(
    {
        'secret',
        'access_token',
        'token',
        'token_prefix',
        'has_secret',
        'authorization_header_set',
        'enable_magic_link',
        'magic_link_effective',
        'magic_link_globally_enabled',
    }
)
_NO_RESTORE_UNDER = frozenset({'user_metadata', 'data', 'envelope', 'arguments'})


class _McpRequestFactory(APIRequestFactory):
    """JSON-encode tool bodies.

    shellui-django 0.5.1 passes the tool body as ``data=<dict>`` with the default
    ``application/octet-stream`` content type. Django then stringifies the dict, and
    DRF rejects the media type before the view runs.
    """

    def generic(self, method, path, data='', content_type='application/octet-stream', secure=False, **extra):
        if isinstance(data, (dict, list)):
            data, content_type = self._encode_data(data, format='json')
        return super().generic(method, path, data, content_type, secure, **extra)


def _restore_disclosed_fields(original, redacted, markers, *, parent_key: str = ''):
    if parent_key in _NO_RESTORE_UNDER:
        return redacted
    if isinstance(original, list) and isinstance(redacted, list):
        restored = [
            _restore_disclosed_fields(item, red_item, markers, parent_key=parent_key)
            for item, red_item in zip(original, redacted, strict=False)
        ]
        if len(redacted) > len(original):
            restored.extend(redacted[len(original) :])
        return restored
    if not isinstance(original, dict) or not isinstance(redacted, dict):
        return redacted
    out = dict(redacted)
    for key, value in original.items():
        node = markers.get(str(key)) if isinstance(markers, dict) else None
        if isinstance(node, dict) and node.get('secret'):
            continue
        if key in _DISCLOSED_RESULT_KEYS and out.get(key) == '[redacted]':
            out[key] = value
            continue
        children = node.get('children') if isinstance(node, dict) else {}
        if key in out:
            out[key] = _restore_disclosed_fields(value, out[key], children or {}, parent_key=str(key))
    return out


def _install_result_redaction() -> None:
    import shellui_django.mcp.server as server_mod
    from django.core.serializers.json import DjangoJSONEncoder

    if getattr(server_mod, '_identity_result_redaction_installed', False):
        return
    # Replace only this module's json binding. Tool results are response.data
    # (datetimes included) and the library dumps them with no encoder.
    # Argument hashes already pass default= and stay on the stdlib encoder.
    real_json = server_mod.json

    class _ResultJson:
        def dumps(self, obj, *args, **kwargs):
            if 'cls' not in kwargs and 'default' not in kwargs:
                kwargs['cls'] = DjangoJSONEncoder
            return real_json.dumps(obj, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(real_json, name)

    server_mod.json = _ResultJson()
    # shellui-django 0.5.1 keeps decision.allowed false after a granted approval, so the
    # call returns the gate reason and never runs the view (and consume already burned
    # the single-use approval). The approval block still returns when the grant is missing.
    original_decide = server_mod.decide_write

    def decide_write(**kwargs):
        decision = original_decide(**kwargs)
        if decision.needs_approval:
            decision.allowed = True
        return decision

    server_mod.decide_write = decide_write
    original = server_mod.redact_mapping

    def redact_mapping(data, *, read_sensitive, markers=None):
        if not _mcp_result_redaction.get():
            return original(data, read_sensitive=read_sensitive, markers=markers)
        _mcp_result_redaction.set(False)
        redacted = original(data, read_sensitive=read_sensitive, markers=markers)
        if not isinstance(data, dict):
            return redacted
        return _restore_disclosed_fields(data, redacted, markers or {})

    server_mod.redact_mapping = redact_mapping
    server_mod._identity_result_redaction_installed = True


_install_result_redaction()


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
    _server._factory = _McpRequestFactory()
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
    duration_ms = entry.get('duration_ms')
    if not isinstance(duration_ms, (int, float)):
        started = _mcp_tool_call_started_at.get()
        duration_ms = max(0, int((time.monotonic() - started) * 1000)) if started is not None else 0
    else:
        duration_ms = max(0, int(duration_ms))
    McpCallLog.objects.create(
        agent=agent,
        company_id=company_id,
        service=entry.get('service') or 'identity',
        tool=entry.get('tool') or '',
        http_method=entry.get('method') or '',
        path=entry.get('path') or '',
        status_code=int(entry.get('status') or 0),
        duration_ms=duration_ms,
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
    # simplejwt returns a token object; the RS256 agent path returns the decoded claims dict.
    claims = dict(getattr(token, 'payload', token))
    if not access_token_audience_matches(claims, expected):
        return None
    request.user = _user
    return claims


@csrf_exempt
def mcp_endpoint(request: HttpRequest):
    claims = _agent_claims(request)
    timer: contextvars.Token | None = None
    redact_token: contextvars.Token | None = None
    if request.method == 'POST':
        try:
            payload = json.loads(request.body.decode('utf-8') or '{}')
            if isinstance(payload, dict) and payload.get('method') == 'tools/call':
                timer = _mcp_tool_call_started_at.set(time.monotonic())
                redact_token = _mcp_result_redaction.set(True)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    try:
        return _get_server().handle(request, agent_claims=claims)
    finally:
        if redact_token is not None:
            _mcp_result_redaction.reset(redact_token)
        if timer is not None:
            _mcp_tool_call_started_at.reset(timer)
