"""Internal service-to-identity APIs (signed assertions, no user tokens)."""

from __future__ import annotations

from datetime import timedelta
import uuid

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from shellui_django.mcp.internal import (
    APPROVAL_AUDIENCE,
    APPROVAL_SCOPE,
    CALL_LOG_AUDIENCE,
    CALL_LOG_SCOPE,
    REVOCATION_AUDIENCE,
    REVOCATION_SCOPE,
    InternalAssertionError,
)
from shellui_django.mcp.masking import redact_mapping

from apps.actions.event_log import record_event
from apps.actions.registry import get_event_type
from apps.agents.approval_audit import record_approval_expired_once
from apps.agents.approval_decisions import (
    ApprovalDecisionError,
    client_allow,
    client_allow_session,
    client_deny,
)
from apps.agents.approval_internal import (
    approval_binding_from_claims,
    lookup_approval_row,
    public_approval_status,
)
from apps.agents.approval_links import sign_approval_fallback_token
from apps.agents.approval_session import (
    active_session_grant,
    revoke_session_grant,
    session_allows_non_destructive_write,
)
from apps.agents.approval_authority import (
    agent_matches_approval_authority,
    approval_row_stale_for_agent,
    parse_approval_authority_claims,
)
from apps.agents.internal_callers import verify_caller_assertion
from apps.agents.call_log_outcome import CANONICAL_OUTCOMES, canonical_outcome, normalized_resource_label
from apps.agents.mcp_audit_codes import sanitize_error_code
from apps.agents.models import Agent, McpApprovalRequest, McpCallLog
from apps.agents.tokens import company_name_for_agent
from apps.agents.revocation import (
    REVOCATION_CACHE_SECONDS,
    active_max_grant_version,
    blocked_agent_ids,
    blocked_agent_snapshots,
)
from apps.agents.revocation_jwt import compute_revocation_policy_version, sign_revocation_list_response
from apps.federation.signing import TokenError


def _identity_origin() -> str:
    return (getattr(settings, 'JWT_ISSUER', '') or '').rstrip('/')


def _approval_target_from_body(body: dict) -> str:
    target = str(body.get('target') or '').strip()
    if target:
        return target[:500]
    method = str(body.get('method') or '').strip().upper()
    path = str(body.get('path') or '').strip()
    if method and path:
        return f'{method} {path}'[:500]
    if path:
        return path[:500]
    return ''


def _assertion_from_request(request) -> str:
    auth = request.headers.get('Authorization') or ''
    if auth.lower().startswith('bearer '):
        return auth[7:].strip()
    return str(request.data.get('assertion') or '').strip()


def _approval_assertion_claims(request):
    try:
        verified = verify_caller_assertion(
            _assertion_from_request(request),
            audience=APPROVAL_AUDIENCE,
            scope=APPROVAL_SCOPE,
            target=_identity_origin(),
        )
    except InternalAssertionError as exc:
        return None, None, Response({'error': exc.message}, status=exc.status)
    binding = approval_binding_from_claims(verified.claims)
    if binding is None:
        return None, None, Response({'error': 'Invalid assertion claims.'}, status=status.HTTP_400_BAD_REQUEST)
    return verified.claims, verified.caller, None


def _approval_live_authority(claims: dict, binding: dict) -> Response | None:
    auth, err = parse_approval_authority_claims(claims)
    if err:
        return Response({'error': err}, status=status.HTTP_400_BAD_REQUEST)
    assert auth is not None
    try:
        agent = Agent.objects.only(
            'id',
            'grant_version',
            'global_company_id',
            'company_binding_version',
            'company_id',
        ).get(pk=binding['agent_id'], company_id=binding['company_id'])
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)
    if not agent_matches_approval_authority(agent, auth):
        return Response({'error': 'Approval authority mismatch.'}, status=status.HTTP_409_CONFLICT)
    return None


class McpRevocationListView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        try:
            verify_caller_assertion(
                _assertion_from_request(request),
                audience=REVOCATION_AUDIENCE,
                scope=REVOCATION_SCOPE,
                target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        company_id = request.query_params.get('company_id')
        cid = int(company_id) if company_id and str(company_id).isdigit() else None
        revoked_ids = blocked_agent_ids(company_id=cid)
        agents = blocked_agent_snapshots(company_id=cid)
        policy_ver = compute_revocation_policy_version(
            revoked_ids=revoked_ids,
            agents=agents,
            cache_seconds=REVOCATION_CACHE_SECONDS,
            max_active_grant_version=active_max_grant_version(company_id=cid),
        )
        try:
            revocation_assertion = sign_revocation_list_response(
                revoked_agent_ids=revoked_ids,
                agents=agents,
                cache_seconds=REVOCATION_CACHE_SECONDS,
                revocation_policy_version=policy_ver,
            )
        except TokenError:
            return Response(
                {'error': 'Revocation list signing is not configured.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        payload = {
            'revoked_agent_ids': revoked_ids,
            'agents': agents,
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_policy_version': policy_ver,
            'revocation_assertion': revocation_assertion,
        }
        response = Response(payload)
        response['Cache-Control'] = f'private, max-age={REVOCATION_CACHE_SECONDS}'
        return response


class McpInternalApprovalCreateView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            verified = verify_caller_assertion(
                _assertion_from_request(request),
                audience=APPROVAL_AUDIENCE,
                scope=APPROVAL_SCOPE,
                target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        claims = verified.claims
        binding = approval_binding_from_claims(claims)
        if binding is None:
            return Response({'error': 'Invalid assertion claims.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            agent = Agent.objects.get(pk=binding['agent_id'], company_id=binding['company_id'])
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)
        if not agent.is_active:
            return Response({'error': 'Agent inactive.'}, status=status.HTTP_403_FORBIDDEN)
        live_err = _approval_live_authority(claims, binding)
        if live_err is not None:
            return live_err
        body = request.data if isinstance(request.data, dict) else {}
        args = body.get('arguments') if isinstance(body.get('arguments'), dict) else {}
        redacted = redact_mapping(args, read_sensitive=False)
        target = _approval_target_from_body(body)
        is_destructive = bool(body.get('is_destructive'))
        short_action_summary = str(body.get('short_action_summary') or '')[:500]
        expires_at = timezone.now() + timedelta(minutes=10)
        snap_gv = int(agent.grant_version or 0)
        snap_gc = agent.global_company_id
        snap_cb = agent.company_binding_version
        row, created = McpApprovalRequest.objects.get_or_create(
            agent=agent,
            arguments_hash=binding['arguments_hash'],
            service=binding['service'],
            action=binding['action'],
            status=McpApprovalRequest.STATUS_PENDING,
            defaults={
                'company_id': binding['company_id'],
                'target': target,
                'arguments_redacted': redacted,
                'expires_at': expires_at,
                'is_destructive': is_destructive,
                'short_action_summary': short_action_summary,
                'authority_grant_version': snap_gv,
                'authority_global_company_id': snap_gc,
                'authority_company_binding_version': snap_cb,
            },
        )
        if not created:
            if row.expires_at <= timezone.now():
                row.expires_at = expires_at
                row.arguments_redacted = redacted
                row.target = target or row.target
                row.is_destructive = is_destructive
                row.short_action_summary = short_action_summary or row.short_action_summary
                row.authority_grant_version = snap_gv
                row.authority_global_company_id = snap_gc
                row.authority_company_binding_version = snap_cb
                row.save(
                    update_fields=[
                        'expires_at',
                        'arguments_redacted',
                        'target',
                        'is_destructive',
                        'short_action_summary',
                        'authority_grant_version',
                        'authority_global_company_id',
                        'authority_company_binding_version',
                    ]
                )
            elif row.status == McpApprovalRequest.STATUS_PENDING:
                row.authority_grant_version = snap_gv
                row.authority_global_company_id = snap_gc
                row.authority_company_binding_version = snap_cb
                row.save(
                    update_fields=[
                        'authority_grant_version',
                        'authority_global_company_id',
                        'authority_company_binding_version',
                    ]
                )
        token = sign_approval_fallback_token(str(row.id))
        fallback_path = f'/oauth/mcp/approval/{row.id}?token={token}'
        return Response(
            {
                'id': str(row.id),
                'status': row.status,
                'expires_at': row.expires_at.isoformat(),
                'is_destructive': row.is_destructive,
                'fallback_path': fallback_path,
            }
        )


class McpInternalApprovalStateView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, _caller, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        live_err = _approval_live_authority(claims, binding)
        if live_err is not None:
            return live_err
        row = lookup_approval_row(binding)
        if row is None:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        try:
            agent = Agent.objects.get(pk=binding['agent_id'], company_id=binding['company_id'])
        except Agent.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        if approval_row_stale_for_agent(agent, row):
            return Response({'error': 'Approval authority stale.'}, status=status.HTTP_409_CONFLICT)
        now = timezone.now()
        public_status = public_approval_status(row, now=now)
        if public_status == 'expired':
            record_approval_expired_once(row)
        payload = {'status': public_status}
        if public_status == 'approved':
            payload['id'] = str(row.id)
        return Response(payload)


class McpInternalApprovalDecideView(APIView):
    """Client/gateway decisions: allow, deny, or allow_session (non-destructive only)."""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, caller, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        live_err = _approval_live_authority(claims, binding)
        if live_err is not None:
            return live_err
        body = request.data if isinstance(request.data, dict) else {}
        approval_id = str(body.get('approval_id') or '').strip()
        decision = str(body.get('decision') or '').strip().lower()
        actor_email = str(body.get('actor_email') or '').strip() or None
        connection_id = str(body.get('connection_id') or '').strip()
        if not approval_id:
            return Response({'error': 'approval_id required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            row = McpApprovalRequest.objects.select_related('agent').get(
                pk=approval_id,
                agent_id=binding['agent_id'],
                company_id=binding['company_id'],
                service=binding['service'],
                action=binding['action'],
                arguments_hash=binding['arguments_hash'],
            )
        except McpApprovalRequest.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        if approval_row_stale_for_agent(row.agent, row):
            return Response({'error': 'Approval authority stale.'}, status=status.HTTP_409_CONFLICT)
        try:
            if decision in ('allow', 'approve'):
                result = client_allow(row, actor_email=actor_email)
            elif decision in ('deny', 'reject'):
                result = client_deny(row, actor_email=actor_email)
            elif decision in ('allow_session', 'session'):
                result = client_allow_session(
                    row,
                    connection_id=connection_id,
                    actor_email=actor_email,
                    caller_name=caller.name,
                    assertion_claims=claims,
                )
            else:
                return Response({'error': 'decision must be allow, deny, or allow_session.'}, status=status.HTTP_400_BAD_REQUEST)
        except ApprovalDecisionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        return Response({'approval_id': str(result.row.id), 'status': result.row.status, 'audit_status': result.audit_status})


class McpInternalApprovalSessionCheckView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, _caller, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        body = request.data if isinstance(request.data, dict) else {}
        connection_id = str(body.get('connection_id') or '').strip()
        is_destructive = bool(body.get('is_destructive'))
        auth_err = _approval_live_authority(claims, binding)
        if auth_err is not None:
            return auth_err
        grant = active_session_grant(
            agent_id=binding['agent_id'],
            company_id=binding['company_id'],
            connection_id=connection_id,
        )
        allowed = not is_destructive and grant is not None
        payload: dict = {'session_allowed': allowed}
        if allowed:
            assert grant is not None
            agent = Agent.objects.only(
                'grant_version',
                'global_company_id',
                'company_binding_version',
                'setup_company_id',
                'setup_context_expires_at',
                'setup_new_company_grant',
                'setup_mcp_session_ttl_seconds',
                'company_id',
            ).get(pk=binding['agent_id'])
            pv = int(getattr(agent, 'grant_version', 0) or 0)
            cb = getattr(agent, 'company_binding_version', None)
            now = timezone.now()
            setup_cid = getattr(agent, 'setup_company_id', None)
            setup_until = getattr(agent, 'setup_context_expires_at', None)
            setup_unix = None
            new_grant = bool(getattr(agent, 'setup_new_company_grant', False))
            setup_ttl = getattr(agent, 'setup_mcp_session_ttl_seconds', None)
            gc = getattr(agent, 'global_company_id', None)
            setup_extended = (
                new_grant
                and gc is not None
                and cb is not None
                and setup_ttl is not None
                and setup_cid is not None
                and setup_until is not None
                and int(setup_cid) == int(binding['company_id'])
                and setup_until > now
            )
            if setup_extended:
                setup_unix = int(setup_until.timestamp())
            elif (
                setup_cid is not None
                and setup_until is not None
                and int(setup_cid) == int(binding['company_id'])
                and setup_until > now
            ):
                setup_unix = int(setup_until.timestamp())
            payload['expires_at'] = grant.expires_at.isoformat()
            payload['grant_version'] = pv
            if cb is not None:
                payload['company_binding_version'] = int(cb)
            if setup_unix is not None:
                payload['setup_expires_at'] = setup_unix
            if setup_extended:
                payload['setup_flow'] = True
                payload['mcp_new_company_grant'] = True
                payload['mcp_session_ttl_seconds'] = int(setup_ttl)
        return Response(payload)


class McpInternalApprovalSessionRevokeView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, _caller, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        body = request.data if isinstance(request.data, dict) else {}
        connection_id = str(body.get('connection_id') or '').strip()
        updated = revoke_session_grant(
            agent_id=binding['agent_id'],
            company_id=binding['company_id'],
            connection_id=connection_id,
        )
        return Response({'revoked': updated > 0})


class McpInternalApprovalConsumeView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, _caller, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        live_err = _approval_live_authority(claims, binding)
        if live_err is not None:
            return live_err
        body = request.data if isinstance(request.data, dict) else {}
        approval_id_str = str(body.get('approval_id') or '').strip()
        if not approval_id_str:
            return Response({'error': 'approval_id required.'}, status=status.HTTP_400_BAD_REQUEST)
        now = timezone.now()
        with transaction.atomic():
            try:
                row = (
                    McpApprovalRequest.objects.select_for_update()
                    .filter(
                        pk=approval_id_str,
                        agent_id=binding['agent_id'],
                        company_id=binding['company_id'],
                        service=binding['service'],
                        action=binding['action'],
                        arguments_hash=binding['arguments_hash'],
                    )
                    .get()
                )
            except McpApprovalRequest.DoesNotExist:
                return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
            if approval_row_stale_for_agent(row.agent, row):
                return Response({'error': 'Approval authority stale.', 'consumed': False}, status=status.HTTP_409_CONFLICT)
            if row.status == McpApprovalRequest.STATUS_EXECUTED:
                return Response(
                    {'error': 'Approval already consumed.', 'consumed': False},
                    status=status.HTTP_409_CONFLICT,
                )
            if row.status != McpApprovalRequest.STATUS_APPROVED or row.expires_at <= now:
                return Response(
                    {'error': 'Approval is not consumable.', 'consumed': False},
                    status=status.HTTP_409_CONFLICT,
                )
            row.status = McpApprovalRequest.STATUS_EXECUTED
            row.executed_at = now
            row.save(update_fields=['status', 'executed_at'])
        return Response({'consumed': True})


class McpInternalCallLogView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            verify_caller_assertion(
                _assertion_from_request(request),
                audience=CALL_LOG_AUDIENCE,
                scope=CALL_LOG_SCOPE,
                target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        body = request.data if isinstance(request.data, dict) else {}
        agent_id = str(body.get('agent_id') or '')
        company_id = body.get('company_id')
        if not agent_id or company_id is None:
            return Response({'error': 'agent_id and company_id required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            agent = Agent.objects.get(pk=agent_id, company_id=company_id)
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)
        args = body.get('arguments') if isinstance(body.get('arguments'), dict) else {}
        ip_raw = str(body.get('client_ip') or '').strip()
        client_ip = ip_raw if ip_raw else None
        result = str(body.get('result') or '')[:32]
        status_code = int(body.get('status') or 0)
        duration_ms = int(body.get('duration_ms') or 0)
        tool_s = str(body.get('tool') or '')[:255]
        method_s = str(body.get('method') or '')[:10]
        path_s = str(body.get('path') or '')[:500]
        path_s = path_s.split('?', 1)[0].split('#', 1)[0].strip()[:500]
        outcome_raw = str(body.get('outcome') or '').strip().lower()
        if outcome_raw and outcome_raw not in CANONICAL_OUTCOMES:
            return Response({'error': 'Invalid outcome.'}, status=status.HTTP_400_BAD_REQUEST)
        outcome = canonical_outcome(outcome_raw or None, status_code=status_code)
        operation_title = str(body.get('operation_title') or '').strip()[:200]
        if not operation_title:
            operation_title = (tool_s or path_s or 'mcp_call')[:200]
        access_kind = str(body.get('access_kind') or '').strip().lower()[:32]
        if access_kind not in ('read', 'write', 'destructive', 'unknown', ''):
            return Response({'error': 'Invalid access_kind.'}, status=status.HTTP_400_BAD_REQUEST)
        if not access_kind:
            access_kind = 'unknown'
        resource_label_in = str(body.get('resource_label') or '').strip()[:500]
        resource_label_in = resource_label_in.split('?', 1)[0].split('#', 1)[0].strip()[:500]
        resource_label = resource_label_in or normalized_resource_label(tool_s, method_s, path_s)
        company_name_in = str(body.get('company_name') or '').strip()[:255]
        company_name = company_name_in or company_name_for_agent(agent)
        approval_id = None
        raw_approval = body.get('approval_id')
        if raw_approval not in (None, ''):
            try:
                approval_id = uuid.UUID(str(raw_approval))
            except (ValueError, TypeError):
                return Response({'error': 'Invalid approval_id.'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                appr = McpApprovalRequest.objects.get(pk=approval_id)
            except McpApprovalRequest.DoesNotExist:
                approval_id = None
            else:
                if (
                    str(appr.agent_id) != str(agent.id)
                    or int(appr.company_id) != int(company_id)
                    or str(appr.service or '') != str(body.get('service') or '')[:32]
                ):
                    approval_id = None
        error_code_raw = body.get('error_code')
        error_code_val = sanitize_error_code(error_code_raw) or ''
        row = McpCallLog.objects.create(
            agent=agent,
            company_id=company_id,
            service=str(body.get('service') or '')[:32],
            tool=tool_s,
            http_method=method_s,
            path=path_s,
            status_code=status_code,
            duration_ms=duration_ms,
            result=result,
            operation_title=operation_title,
            access_kind=access_kind,
            outcome=outcome,
            resource_label=resource_label,
            company_name=company_name,
            approval_id=approval_id,
            error_code=error_code_val,
            client_ip=client_ip,
            arguments_redacted=redact_mapping(args, read_sensitive=False),
        )
        event = get_event_type('identity.mcp.call')
        if event:
            record_event(
                event,
                agent.company,
                {
                    'agent_id': str(agent.id),
                    'service': row.service,
                    'tool': row.tool,
                    'status_code': row.status_code,
                },
            )
        return Response({'id': row.id}, status=status.HTTP_201_CREATED)
