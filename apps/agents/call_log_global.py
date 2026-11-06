"""Dashboard-signed global company activity for an existing provisioned company.

Does not create a regional company, does not copy a global agent id into ``Agent.id``,
and does not store tool arguments, query, body, email, or client IP.

Unbound first-company approvals are not accepted here. Owner approval lists and the
fallback page require a regional ``Company`` and ``Agent``. There is no row to show
before SaaS has provisioned the company.
"""

from __future__ import annotations

import uuid

from rest_framework import status
from rest_framework.response import Response

from apps.actions.event_log import record_event
from apps.actions.registry import get_event_type
from apps.agents.approval_global import (
    ensure_global_approval_claims,
    global_agent_revoked,
    global_approval_live_binding_ok,
    global_user_sub_is_company_owner,
    link_global_approval_to_regional_agent,
    provisioned_company_for_global_uuid,
)
from apps.agents.call_log_internal import fixed_resource_label_for_service, safe_operation_title
from apps.agents.call_log_outcome import canonical_outcome_ingest
from apps.agents.internal_callers import VerifiedAssertion
from apps.agents.json_strict import strict_non_negative_int
from apps.agents.mcp_audit_codes import sanitize_error_code
from apps.agents.models import Agent, McpApprovalRequest, McpCallLog

GLOBAL_AUDIT_SCOPE = 'global_company'

GLOBAL_AUDIT_CLAIM_KEYS = frozenset(
    {
        'agent_audit_scope',
        'global_agent_id',
        'global_company_id',
        'global_user_sub',
        'grant_version',
        'company_binding_version',
    }
)

_BODY_KEYS = frozenset(
    {
        'service',
        'tool',
        'method',
        'path',
        'outcome',
        'access_kind',
        'status',
        'duration_ms',
        'error_code',
        'company_id',
        'agent_id',
        'global_company_id',
        'company_binding_version',
        'grant_version',
        'approval_id',
    }
)


def claims_use_global_audit(claims: dict) -> bool:
    return any(key in claims for key in GLOBAL_AUDIT_CLAIM_KEYS)


def select_sole_active(agents: list[Agent]) -> tuple[Agent | None, str]:
    """Return the one active row, or none. ``ambiguous`` when more than one is active."""
    active = [agent for agent in agents if agent.is_active]
    if len(active) > 1:
        return None, 'ambiguous'
    if len(active) == 1:
        return active[0], 'one'
    return None, 'none'


def ingest_global_dashboard_activity(request, verified: VerifiedAssertion, body: dict) -> Response:
    if verified.caller.name != 'dashboard':
        return Response(
            {'error': 'Global company activity requires a dashboard-signed assertion.'},
            status=status.HTTP_403_FORBIDDEN,
        )
    if request.query_params:
        return Response({'error': 'Query parameters are not accepted.'}, status=status.HTTP_400_BAD_REQUEST)
    unknown = set(body.keys()) - _BODY_KEYS
    if unknown:
        return Response({'error': 'Unexpected request fields.'}, status=status.HTTP_400_BAD_REQUEST)

    claims = verified.claims
    if claims.get('agent_audit_scope') != GLOBAL_AUDIT_SCOPE:
        return Response({'error': 'Invalid agent_audit_scope.'}, status=status.HTTP_400_BAD_REQUEST)
    missing = [key for key in GLOBAL_AUDIT_CLAIM_KEYS if key not in claims or claims.get(key) in (None, '')]
    if missing:
        return Response({'error': 'Global activity assertion is missing signed claims.'}, status=status.HTTP_400_BAD_REQUEST)

    meta = ensure_global_approval_claims(claims)
    if meta is None:
        return Response({'error': 'Invalid global activity claims.'}, status=status.HTTP_400_BAD_REQUEST)
    grant_version = strict_non_negative_int(claims.get('grant_version'))
    if grant_version is None:
        return Response({'error': 'grant_version must be a JSON non-negative integer.'}, status=status.HTTP_400_BAD_REQUEST)
    if global_agent_revoked(meta['global_agent_id']):
        return Response({'error': 'Global agent is revoked.'}, status=status.HTTP_403_FORBIDDEN)

    pc = provisioned_company_for_global_uuid(meta['global_company_id'])
    if pc is None:
        return Response(
            {'error': 'Provisioned company not found. Unbound first-company activity is not supported.'},
            status=status.HTTP_404_NOT_FOUND,
        )
    if not global_user_sub_is_company_owner(global_user_sub=meta['global_user_sub'], company=pc.company):
        return Response({'error': 'Actor is not a verified company owner.'}, status=status.HTTP_403_FORBIDDEN)
    if not global_approval_live_binding_ok(meta, authority_grant_version=grant_version):
        return Response({'error': 'Global activity authority mismatch.'}, status=status.HTTP_409_CONFLICT)

    company_err = _optional_company_id(body, expected=int(pc.company_id))
    if company_err is not None:
        return company_err
    signed_err = _signed_body_matches(body, meta=meta, grant_version=grant_version)
    if signed_err is not None:
        return signed_err
    agent_err = _body_agent_id_is_not_regional_pk(body, global_agent_id=meta['global_agent_id'])
    if agent_err is not None:
        return agent_err

    candidates = list(
        Agent.objects.filter(
            global_agent_id=meta['global_agent_id'],
            company_id=pc.company_id,
            global_company_id=meta['global_company_id'],
            company_binding_version=meta['company_binding_version'],
            grant_version=grant_version,
        )
    )
    agent, choice = select_sole_active(candidates)
    if choice == 'ambiguous':
        return Response({'error': 'Regional agent mapping is ambiguous.'}, status=status.HTTP_409_CONFLICT)

    tool_s = str(body.get('tool') or '')[:255]
    method_s = str(body.get('method') or '')[:10]
    path_s = str(body.get('path') or '')[:500]
    path_s = path_s.split('?', 1)[0].split('#', 1)[0].strip()[:500]
    outcome_raw = str(body.get('outcome') or '').strip().lower()
    normalized = canonical_outcome_ingest(outcome_raw or None)
    if not outcome_raw or normalized is None:
        return Response({'error': 'Invalid outcome.' if outcome_raw else 'outcome required.'}, status=status.HTTP_400_BAD_REQUEST)
    outcome = normalized
    access_kind = str(body.get('access_kind') or '').strip().lower()[:32]
    if access_kind not in ('read', 'write', 'destructive', 'unknown', ''):
        return Response({'error': 'Invalid access_kind.'}, status=status.HTTP_400_BAD_REQUEST)
    if not access_kind:
        access_kind = 'unknown'
    service_id = str(body.get('service') or '')[:32]
    resource_label = fixed_resource_label_for_service(service_id=service_id, method=method_s, path=path_s)
    if resource_label is None:
        return Response({'error': 'Invalid path for service.'}, status=status.HTTP_400_BAD_REQUEST)

    approval_uuid, approval_err = _parse_approval_id(body)
    if approval_err is not None:
        return approval_err
    linked, link_err = _link_approval(
        approval_uuid,
        agent=agent,
        service_id=service_id,
        tool_s=tool_s,
    )
    if link_err is not None:
        return link_err

    from apps.agents.internal_views import _destructive_call_log_outcome_error

    if access_kind == 'destructive':
        if agent is None or not bool(getattr(agent, 'global_max_destructive', False)):
            return Response(
                {'error': 'Destructive tools are not allowed for this agent.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        destructive_err = _destructive_call_log_outcome_error(outcome=outcome, approval_id=approval_uuid)
        if destructive_err is not None:
            return Response({'error': destructive_err}, status=status.HTTP_400_BAD_REQUEST)
    elif linked is not None and linked.is_destructive:
        return Response(
            {'error': 'destructive approval_id requires access_kind destructive.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        status_code = int(body.get('status') or 0)
        duration_ms = int(body.get('duration_ms') or 0)
    except (TypeError, ValueError):
        return Response({'error': 'Invalid status or duration_ms.'}, status=status.HTTP_400_BAD_REQUEST)
    if status_code < 0 or duration_ms < 0:
        return Response({'error': 'Invalid status or duration_ms.'}, status=status.HTTP_400_BAD_REQUEST)

    row = McpCallLog.objects.create(
        agent=agent,
        global_agent_id=meta['global_agent_id'],
        global_company_id=meta['global_company_id'],
        company_id=pc.company_id,
        service=service_id,
        tool=tool_s,
        http_method=method_s,
        path=path_s,
        status_code=status_code,
        duration_ms=duration_ms,
        result='',
        operation_title=safe_operation_title(tool_s),
        access_kind=access_kind,
        outcome=outcome,
        resource_label=resource_label,
        company_name=pc.company.name or '',
        approval_id=approval_uuid,
        error_code=sanitize_error_code(body.get('error_code')) or '',
        client_ip=None,
        arguments_redacted={},
    )
    event = get_event_type('identity.mcp.call')
    if event:
        payload = {
            'service': row.service,
            'tool': row.tool,
            'status_code': row.status_code,
        }
        if agent is not None:
            payload['agent_id'] = str(agent.id)
        record_event(event, pc.company, payload)
    return Response({'id': row.id}, status=status.HTTP_201_CREATED)


def _optional_company_id(body: dict, *, expected: int) -> Response | None:
    if 'company_id' not in body or body.get('company_id') in (None, ''):
        return None
    cid = strict_non_negative_int(body.get('company_id'))
    if cid is None or cid <= 0:
        return Response(
            {'error': 'company_id must be the provisioned regional company id.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if cid != expected:
        return Response({'error': 'company_id does not match the provisioned company.'}, status=status.HTTP_400_BAD_REQUEST)
    return None


def _signed_body_matches(body: dict, *, meta: dict, grant_version: int) -> Response | None:
    if 'global_company_id' in body and body.get('global_company_id') not in (None, ''):
        raw = body.get('global_company_id')
        if type(raw) is not str:
            return Response({'error': 'global_company_id must be a uuid string.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            parsed = uuid.UUID(raw.strip())
        except (TypeError, ValueError):
            return Response({'error': 'Invalid global_company_id.'}, status=status.HTTP_400_BAD_REQUEST)
        if parsed != meta['global_company_id']:
            return Response({'error': 'global_company_id does not match the signed claim.'}, status=status.HTTP_400_BAD_REQUEST)
    if 'company_binding_version' in body and body.get('company_binding_version') not in (None, ''):
        parsed_cb = strict_non_negative_int(body.get('company_binding_version'))
        if parsed_cb is None or parsed_cb != int(meta['company_binding_version']):
            return Response(
                {'error': 'company_binding_version does not match the signed claim.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
    if 'grant_version' in body and body.get('grant_version') not in (None, ''):
        parsed_gv = strict_non_negative_int(body.get('grant_version'))
        if parsed_gv is None or parsed_gv != grant_version:
            return Response({'error': 'grant_version does not match the signed claim.'}, status=status.HTTP_400_BAD_REQUEST)
    return None


def _body_agent_id_is_not_regional_pk(body: dict, *, global_agent_id: uuid.UUID) -> Response | None:
    if 'agent_id' not in body or body.get('agent_id') in (None, ''):
        return None
    raw = body.get('agent_id')
    if type(raw) is not str or not raw.strip():
        return Response({'error': 'agent_id must be a uuid string.'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        parsed = uuid.UUID(raw.strip())
    except (TypeError, ValueError):
        return Response({'error': 'Invalid agent_id.'}, status=status.HTTP_400_BAD_REQUEST)
    if parsed != global_agent_id:
        return Response(
            {'error': 'agent_id must equal the signed global_agent_id and is not a regional primary key.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    return None


def _parse_approval_id(body: dict) -> tuple[uuid.UUID | None, Response | None]:
    if 'approval_id' not in body or body.get('approval_id') in (None, ''):
        return None, None
    try:
        return uuid.UUID(str(body.get('approval_id'))), None
    except (TypeError, ValueError):
        return None, Response({'error': 'Invalid approval_id.'}, status=status.HTTP_400_BAD_REQUEST)


def _authority_snapshot_matches(agent: Agent, appr: McpApprovalRequest) -> bool:
    if int(getattr(appr, 'authority_grant_version', 0) or 0) != int(agent.grant_version or 0):
        return False
    agc = getattr(agent, 'global_company_id', None)
    agcb = getattr(agent, 'company_binding_version', None)
    snap_gc = getattr(appr, 'authority_global_company_id', None)
    snap_cb = getattr(appr, 'authority_company_binding_version', None)
    if agc is None:
        return snap_gc is None and snap_cb is None
    return snap_gc == agc and snap_cb is not None and int(snap_cb) == int(agcb or 0)


def _link_approval(
    approval_id: uuid.UUID | None,
    *,
    agent: Agent | None,
    service_id: str,
    tool_s: str,
) -> tuple[McpApprovalRequest | None, Response | None]:
    if approval_id is None:
        return None, None
    if agent is None:
        return None, Response(
            {'error': 'approval cannot be linked without one regional agent fingerprint.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        appr = McpApprovalRequest.objects.get(pk=approval_id)
    except McpApprovalRequest.DoesNotExist:
        return None, Response({'error': 'approval row not found.'}, status=status.HTTP_404_NOT_FOUND)
    if str(appr.service or '') != service_id or str(appr.action or '')[:255] != tool_s[:255]:
        return None, Response({'error': 'approval_id does not match this call.'}, status=status.HTTP_400_BAD_REQUEST)
    if appr.agent_id is None:
        if appr.global_agent_id != agent.global_agent_id or not _authority_snapshot_matches(agent, appr):
            return None, Response({'error': 'approval_id does not match this call.'}, status=status.HTTP_400_BAD_REQUEST)
        link_global_approval_to_regional_agent(appr, agent)
        appr.refresh_from_db()
    from apps.agents.internal_views import _call_log_matches_approval_row

    if not _call_log_matches_approval_row(agent, appr):
        return None, Response({'error': 'approval_id does not match this call.'}, status=status.HTTP_400_BAD_REQUEST)
    return appr, None
