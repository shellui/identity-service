"""Internal service-to-identity APIs (signed assertions, no user tokens)."""

from __future__ import annotations

from datetime import timedelta

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
    build_mcp_revocation_list_response_assertion,
)
from shellui_django.mcp.masking import redact_mapping

from apps.actions.event_log import record_event
from apps.actions.registry import get_event_type
from apps.agents.approval_internal import (
    approval_binding_from_claims,
    lookup_approval_row,
    public_approval_status,
)
from apps.agents.internal_callers import verify_caller_assertion
from apps.agents.models import Agent, McpApprovalRequest, McpCallLog
from apps.agents.revocation import REVOCATION_CACHE_SECONDS, blocked_agent_ids, blocked_agent_snapshots


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


def _approval_assertion_claims(request) -> tuple[dict | None, Response | None]:
    try:
        claims = verify_caller_assertion(
            _assertion_from_request(request),
            audience=APPROVAL_AUDIENCE,
            scope=APPROVAL_SCOPE,
            target=_identity_origin(),
        )
    except InternalAssertionError as exc:
        return None, Response({'error': exc.message}, status=exc.status)
    binding = approval_binding_from_claims(claims)
    if binding is None:
        return None, Response({'error': 'Invalid assertion claims.'}, status=status.HTTP_400_BAD_REQUEST)
    return claims, None


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
        try:
            revocation_assertion = build_mcp_revocation_list_response_assertion(
                revoked_agent_ids=revoked_ids,
                agents=agents,
                cache_seconds=REVOCATION_CACHE_SECONDS,
            )
        except InternalAssertionError as exc:
            if exc.status == status.HTTP_503_SERVICE_UNAVAILABLE:
                return Response({'error': exc.message}, status=exc.status)
            raise
        payload = {
            'revoked_agent_ids': revoked_ids,
            'agents': agents,
            'cache_seconds': REVOCATION_CACHE_SECONDS,
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
            claims = verify_caller_assertion(
                _assertion_from_request(request),
                audience=APPROVAL_AUDIENCE,
                scope=APPROVAL_SCOPE,
                target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        binding = approval_binding_from_claims(claims)
        if binding is None:
            return Response({'error': 'Invalid assertion claims.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            agent = Agent.objects.get(pk=binding['agent_id'], company_id=binding['company_id'])
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)
        if not agent.is_active:
            return Response({'error': 'Agent inactive.'}, status=status.HTTP_403_FORBIDDEN)
        body = request.data if isinstance(request.data, dict) else {}
        args = body.get('arguments') if isinstance(body.get('arguments'), dict) else {}
        redacted = redact_mapping(args, read_sensitive=False)
        target = _approval_target_from_body(body)
        expires_at = timezone.now() + timedelta(minutes=10)
        row, created = McpApprovalRequest.objects.get_or_create(
            agent=agent,
            arguments_hash=binding['arguments_hash'],
            status=McpApprovalRequest.STATUS_PENDING,
            defaults={
                'company_id': binding['company_id'],
                'service': binding['service'],
                'action': binding['action'],
                'target': target,
                'arguments_redacted': redacted,
                'expires_at': expires_at,
            },
        )
        if not created and row.expires_at <= timezone.now():
            row.expires_at = expires_at
            row.arguments_redacted = redacted
            row.target = target or row.target
            row.save(update_fields=['expires_at', 'arguments_redacted', 'target'])
        return Response({'id': str(row.id), 'status': row.status, 'expires_at': row.expires_at.isoformat()})


class McpInternalApprovalStateView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        row = lookup_approval_row(binding)
        if row is None:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        now = timezone.now()
        public_status = public_approval_status(row, now=now)
        payload = {'status': public_status}
        if public_status == 'approved':
            payload['id'] = str(row.id)
        return Response(payload)


class McpInternalApprovalConsumeView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
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
                        arguments_hash=binding['arguments_hash'],
                    )
                    .get()
                )
            except McpApprovalRequest.DoesNotExist:
                return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
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
        row = McpCallLog.objects.create(
            agent=agent,
            company_id=company_id,
            service=str(body.get('service') or '')[:32],
            tool=str(body.get('tool') or '')[:255],
            http_method=str(body.get('method') or '')[:10],
            path=str(body.get('path') or '')[:500],
            status_code=int(body.get('status') or 0),
            duration_ms=int(body.get('duration_ms') or 0),
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
